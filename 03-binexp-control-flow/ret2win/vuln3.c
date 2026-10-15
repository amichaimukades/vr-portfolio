#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(int code) {
    if (code == 151060) {
        printf("Access granted. Flag: entrypoint{ret2win_success}\n");
        system("/bin/sh");
    }
    else {
        printf("Access denied. Invalid code.\n");
    }
}

void vulnerable(void) {
    char buffer[64];
    puts("Enter data:");
    read(0, buffer, 256);
    puts("Done.");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vulnerable();
    return 0;
}