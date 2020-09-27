#include <stdio.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <limits.h>


void aa(int v)
{
	(void)v;
	int* null = 0;

	__try
	{
		puts("a0");

		__try
		{
			puts("a1");
			*null = 1;
			puts("NEVER");
		}
		__finally
		{
			puts("a3");
		}
		puts("NEVER");
	}
	__except ((puts("a2"),EXCEPTION_EXECUTE_HANDLER))
	{
		puts("a4");
	}
	puts("a5/5");
}

void bb_1(int v)
{
	int* null = 0;

	__try
	{
		if (v == 13) {
			puts("NEVER");
			*null = v;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		puts("NEVER");
	}

	
	if (v == 12) {
		puts("b2");
		*null = v;
	}

	__try
	{
		bb_1(v + 1);
		puts("NEVER");
	}
	__except (((v > 12) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH))
	{
		puts("NEVER");
	}
}

void bb_0(int v)
{
	__try
	{
		puts("b1");
		bb_1(v + 1);
		puts("NEVER");
	}
	__finally
	{
		puts("b5");
	}
}

int bb_filt(unsigned int code, struct _EXCEPTION_POINTERS* ep)
{
	puts("b3");
	if (code == EXCEPTION_ACCESS_VIOLATION) {
		puts("b4");
		return EXCEPTION_EXECUTE_HANDLER;
	}
	return EXCEPTION_CONTINUE_EXECUTION;
}

void bb(int v)
{
	puts("b0");
	__try
	{
		bb_0(v + 1);
	}
	__except (bb_filt(GetExceptionCode(), GetExceptionInformation()))
	{
		puts("b6");
	}
	puts("b7/7");
}

int cc_filt(unsigned int code, struct _EXCEPTION_POINTERS* ep)
{
	switch (code) {
	case EXCEPTION_ACCESS_VIOLATION:
		switch (ep->ExceptionRecord->ExceptionInformation[0]) {
		case 0: // read
			puts("c0");
			break;
		case 1: // write
			puts("c1");
			break;
		case 8: // execute
			puts("c2");
			break;
		}
		break;
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		puts("c3");
		break;
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		puts("c4");
		break;
	case EXCEPTION_BREAKPOINT:
		puts("c5");
		break;
	case EXCEPTION_SINGLE_STEP:
		puts("c6");
		break;
	case EXCEPTION_STACK_OVERFLOW:
		puts("c7");
		break;
	default:
		return EXCEPTION_CONTINUE_SEARCH;
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

extern char ROSTR[];
extern void cc_asm_ii(void);
extern void cc_asm_ss(void);

void cc(int v)
{
	int* addr;
	int t;
	if (v < 0) {
		cc(v);
	}
	v = 0;
	__try {
		while (1) {
			__try
			{
				switch (v) {
				case 0: // read violation
					addr = 0x30;
					v = *addr;
					break;
				case 1: // write violation
					addr = &ROSTR;
					*addr = 'T';

					break;
				case 2: // execute violation
					addr = (int*)"ABCDEFG";
					((void(__stdcall*)(void))addr)();
					break;
				case 3: // illegal inst
					cc_asm_ii();
					break;
				case 4: // div 0
					t = v - 4;
					v = v / t;
					break;
				case 5: // breakpoint
					__debugbreak();
					break;
				case 6: // singlestep
					cc_asm_ss();
					break;
				case 7: // stack overflow
					cc(-1);
					break;
				default:
					puts("NEVER");
					__leave;
				case 8:
					puts("c8");
					return;
				}
			}
			__except (cc_filt(GetExceptionCode(), GetExceptionInformation()))
			{
				v++;
				continue;
			}
			puts("NEVER");
			printf("Failed on v = %d\n", v);
			v++;
		}
	}
	__finally
	{
		puts("c9/9");
	}
	puts("NEVER");
}

int dd_filt(unsigned int code, struct _EXCEPTION_POINTERS* ep)
{
	PCONTEXT ctx;
	if (code == EXCEPTION_BREAKPOINT) {
		ctx = ep->ContextRecord;
		ctx->Rip += 1; // step past 0xCC
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_EXECUTE_HANDLER;
}

void dd(int v)
{
	int* addr = 0;

	__try
	{
		v = *addr;
	}
	__except ((puts("d0"), EXCEPTION_EXECUTE_HANDLER))
	{
		puts("d1");
	}

	for (v = 0; v < 6; v++) {
		__try
		{
			addr = (int*)_alloca(sizeof(int));
			*addr = v;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			puts("NEVER");
		}
	}

	__try
	{
		__debugbreak();

		puts("d2");

		**((int**)addr) = v;
	}
	__except (dd_filt(GetExceptionCode(), GetExceptionInformation()))
	{
		puts("d3");
	}

	puts("d4/4");
}

// include chained calls with chained execption handlers
// include stack allocation later in the function
// turn off inlineing
// funaly, except, filters that continue, search, and handle
// access violation invalid mem read/write, access violation write to ro, access violation execute nx, data type misalignments, illegal instructions, int / 0, int ovf, float / 0, flowt ovf und, brk, single step

int main(int argc, char* argv[])
{
	puts("START");
	aa(0); // simple nested except and finally
	bb(1); // nested across multiple functions
	cc(2); // a bunch of different exception types
	dd(3); // strange function with mid function stack allocations
	puts("DONE");
}