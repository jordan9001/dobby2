from unicorn import *
from unicorn.x86_const import *
import struct


uc = Uc(UC_ARCH_X86, UC_MODE_64)

def insHook(emu, addr, sz, user_data):
    print(f"HOOK: Code @ {addr:x} ({sz:x})")

def rwHook(emu, access, addr, sz, val, user_data):
    print(f"HOOK: mem {access} @ {addr:x} ({sz:x})")

def invalMemHook(emu, access, addr, sz, val, user_data):
    print(f"HOOK: invalid mem {access} @ {addr:x} ({sz:x})")
    return False

def invalInsHook(emu, user_data):
    print(f"HOOK: invalid instruction")
    return False

def intrHook(emu, intno, user_data):
    print(f"HOOK: interrupt {intno:x}")

uc.hook_add(UC_HOOK_CODE, insHook, None, 0, 0xffffffffffffffff)
uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, rwHook, None)
uc.hook_add(UC_HOOK_MEM_INVALID, invalMemHook, None)
uc.hook_add(UC_HOOK_INSN_INVALID, invalInsHook, None)
uc.hook_add(UC_HOOK_INTR, intrHook, None)
# set up page table for ident mapping

tableaddr = 0x00008f0000000000
nexttable = tableaddr
pgshft = 12
entryaddrmask = 0x0000fffffffff000

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

        return (entry & entryaddrmask)

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

def printpagetable(tab, depth=0):
    if depth == 0:
        print(f"pml4 table @ {tab:x}")

    depth += 1

    t = uc.mem_read(tab, 0x1000)
    for i in range(0, 0x1000, 8):
        e = struct.unpack("<Q", t[i:i+8])[0]
        if e & 0x1:
            print(f"{'    ' * depth}{tab+i:016x} [{i//8:x}]: {e:016x}")
            addr = e & entryaddrmask
            if depth < 4:
                addr = e & entryaddrmask
                printpagetable(addr, depth)
            else:
                addr = phys2virt(addr)
                print(f"{'    ' * (depth+1)}= {addr:016x}")

#map page table in page table?
#TODO

# memory map
# 0x111000 rwx
# 0xffffffff00000000 r
# 0xffffffff00001000 rw
# 0xffffffff00002000 er

mapmem(0x111000, 0x3000, UC_PROT_ALL)

mapmem(0xffffffff00000000, 0x1000, UC_PROT_READ)
mapmem(0xffffffff00001000, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
mapmem(0xffffffff00002000, 0x1000, UC_PROT_READ | UC_PROT_EXEC)

# print unicorn's map of physical memory
reg_i = uc.mem_regions()
for r_beg, r_end, r_prot in reg_i:
    print(f"{r_beg:x} - {r_end:x} ({r_prot:x})")

# print the page table
printpagetable(tableaddr)

#code = bytes.fromhex("48b800000000ffffffff488b00ebfe")
code = bytes.fromhex("ebfe")

#addr = 0x111000
addr = 0xffffffff00002000

uc.mem_write(virt2phys(addr), code)

uc.reg_write(UC_X86_REG_RIP, addr)

uc.emu_start(virt2phys(addr), 0, 0, 12)
print("okay")
