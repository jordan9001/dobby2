from unicorn import *
from unicorn.x86_const import *
import struct


uc = Uc(UC_ARCH_X86, UC_MODE_64)

# set up page table for ident mapping

tableaddr = 0x0000800000000000
nexttable = tableaddr
pgshft = 12
pgmask = (~((1 << pgshft) - 1)) & 0xffffffffffffffff

# technically this isn't good because there is a 52 bit limit on physical addrs and 63:M need to be 0
# but let's see if Unicorn lets us do it?
uc.reg_write(UC_X86_REG_CR3, tableaddr)
uc.mem_map(tableaddr, 1 << pgshft, UC_PROT_READ)
nexttable += 1 << pgshft

cr0val = 0
cr0val |= 1 << 0 # Protected Mode
cr0val |= 0 << 1 # Monitor Coprocessor
cr0val |= 0 << 2 # Emulation Mode
cr0val |= 1 << 3 # Task Switched ?
cr0val |= 1 << 4 # Extension Type ?
cr0val |= 1 << 5 # Numeric Error
cr0val |= 1 << 16 # Write Protect
cr0val |= 0 << 18 # Alignment Mask
cr0val |= 0 << 29 # Not Write-through
cr0val |= 0 << 30 # Cache Disable
cr0val |= 1 << 31 # Paging Enabled
uc.reg_write(UC_X86_REG_CR0, cr0val)

cr4val = 0
cr4val |= 0 << 0    # VME
cr4val |= 0 << 1    # PVI
cr4val |= 0 << 2    # TSD
cr4val |= 0 << 3    # DE
cr4val |= 0 << 4    # PSE
cr4val |= 1 << 5    # PAE
cr4val |= 0 << 6    # MCE
cr4val |= 1 << 7    # PGE
cr4val |= 1 << 8    # PCE
cr4val |= 1 << 9    # OSFXSR
cr4val |= 0 << 10   # OSXMMEXCPT
cr4val |= 1 << 11   # UMIP
cr4val |= 1 << 12   # LA57
cr4val |= 0 << 13   # VMXE
cr4val |= 0 << 14   # SMXE
cr4val |= 1 << 17   # PCIDE
cr4val |= 0 << 18   # OSXSAVE
cr4val |= 1 << 20   # SMEP
cr4val |= 1 << 21   # SMAP
cr4val |= 0 << 22   # PKE
cr4val |= 0 << 23   # CET (gross)
cr4val |= 0 << 24   # PKS
uc.reg_write(UC_X86_REG_CR4, cr4val)

def virt2phys(virt):
    return virt & 0x0000ffffffffffff

def phys2virt(phys):
    if phys & (1<<47):
        return phys | 0xffff000000000000
    else:
        return phys

def walkentry(eaddr, sp, prot, isend=False, doalloc=True):
        eaddr = virt2phys(eaddr)
        entry = struct.unpack("<Q", uc.mem_read(eaddr, 8))[0]
        echg = False

        if (entry & 0x1) == 0:
            echg = True
            entry = 0
            if not isend:
                # allocate table
                global nexttable
                assert (nexttable & 0xfff) == 0
                entry = nexttable
                nexttable += 1 << pgshft

                if doalloc:
                    uc.mem_map(entry, 1 << pgshft, UC_PROT_READ)
            else:
                entry = virt2phys(sp<<pgshft)
                if doalloc:
                    uc.mem_map(entry, 1 << pgshft, prot)

            entry |= 1 << 0 # present
            entry |= (0 if sp & (1 << (63 - pgshft)) else 1) << 2 # usermode
            entry |= 1 << 3 # write through
            entry |= 0 << 4 # cache disable
            entry |= 0 << 5 # accessed
            entry |= 0 << 7 # page size

        if (prot & UC_PROT_EXEC) and ((entry & (1 << 63)) == 0):
            echg = True
            entry |= 1 << 63

        if (prot & UC_PROT_WRITE) and ((entry & (1 << 1)) == 0):
            echg = True
            entry |= 1 << 1

        if echg:
            uc.mem_write(eaddr, struct.pack("<Q", entry))

        return (entry & pgmask)

def mapmem(start, size, prot):

    stop = start + size
    # for each page in range
    sp = start >> pgshft
    ep = (stop-1) >> pgshft

    while sp <= ep:

        # 9 bits of PML4 index
        pml4 = (sp >> (39 - pgshft)) & 0x1ff
        # 9 bits of PDPTE
        pdpte = (sp >> (30 - pgshft)) & 0x1ff
        pde = (sp >> (21 - pgshft)) & 0x1ff
        pte = (sp >> (12 - pgshft)) & 0x1ff

        pdpte_table = walkentry(tableaddr + (8 * pml4), sp, prot)
        pde_table = walkentry(pdpte_table + (8 * pdpte), sp, prot)
        pte_table = walkentry(pde_table + (8 * pde), sp, prot)
        walkentry(pte_table + (8 * pte), sp, prot, True)

        sp += 1

#map page table in page table?
#TODO

# memory map
# 0x111000 rwx
# 0xffffffff00000000 r
# 0xffffffff00001000 rw
# 0xffffffff00002000 er

mapmem(0x111000, 0x3000, UC_PROT_ALL)

mapmem(0xffffffff00000000, 0x3000, UC_PROT_READ)
mapmem(0xffffffff00001000, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
mapmem(0xffffffff00002000, 0x1000, UC_PROT_READ | UC_PROT_EXEC)

