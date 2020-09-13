CC=x86_64-w64-mingw32-gcc-win32
CFLAGS=-Wall -Werror -Wextra -Og

all: tester.exe

tester.exe: tester.c tester.S
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f tester.exe
