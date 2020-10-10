#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

extern void test_asm(void);
extern uint32_t get_realpid(void);

int test_rec(int v)
{
    static int stat = 42;

    v = v + v + stat;
    stat += 0x1;
    if (v & 1) {
        v = test_rec(v); 
    } else if (v < 0) {
        v -= test_rec(v);
    }

    return v + stat;
}

int main(int argc, char** argv)
{
    uint32_t pid = 0;
    uint32_t rpid = 0;

    if (argc > 1) {
        pid = GetCurrentProcessId();
        printf("PID = %d\n", pid);
        printf("argv1 = %s\n", argv[1]);
    }
    printf("GLE = %ld\n", GetLastError());

    // test complex memory access based off gs
    rpid = get_realpid();
    if (pid != rpid) {
        
        printf("PIDs don't match!");
    }
    //TODO test memory access with no registers
    // test call chain
    printf("Rec got us %d\n", test_rec(argc));
    //TODO
    // shows up as immediate? if so, how to handle this case?
    test_asm();    

    return 0;
}
