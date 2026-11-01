#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vulnerable(void) {
    char buffer[64];
    puts("Enter data:");
    read(0, buffer, 256);
    puts("Done.");
}

int main(void) {
    char name[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Enter your name:");
    read(0, name, 63);
    printf(name);              /* format-string bug: the user controls the format */
    putchar('\n');
    vulnerable();
    return 0;
}