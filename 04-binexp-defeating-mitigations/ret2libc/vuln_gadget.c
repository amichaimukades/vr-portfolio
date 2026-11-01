#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__asm__(                                   // מגדיר סימבול גלובלי עם הבייטים 5f c3
    ".globl bootstrap_gadget\n"
    ".type  bootstrap_gadget, @function\n"
    "bootstrap_gadget:\n"
    "    pop %rdi\n"                        // 5f
    "    ret\n"                             // c3
);

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