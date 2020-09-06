#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

extern void test_asm(void);

int main(int argc, char** argv)
{
    (void)argv;

    if (argc > 1) {
        printf("PID = %ld\n", GetCurrentProcessId());
        printf("argv1 = %s\n", argv[1]);
    }
    printf("GLE = %ld\n", GetLastError());

    //TODO test complex memory access based off gs
    //TODO test memory access with no registers
    // shows up as immediate? if so, how to handle this case?
    test_asm();    

    return 0;
}
