#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

int main(int argc, char** argv)
{
    (void)argv;
    if (argc > 1) {
        printf("PID = %ld\n", GetCurrentProcessId());
    }
    printf("GLE = %ld\n", GetLastError());

    return 0;
}
