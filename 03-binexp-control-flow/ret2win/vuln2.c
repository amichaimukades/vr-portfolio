#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    printf("Access granted. Flag: entrypoint{ret2win_success}\n");
    system("/bin/sh");
}

void vulnerable(void) {
    char buffer[88];
    puts("Enter data:");
    read(0, buffer, 256);
    puts("Done.");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vulnerable();
    return 0;
}