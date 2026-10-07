#include <stdio.h>
#include <string.h>

int main(void) {
    char input[64];
    int xor = 0x55;
    char secret[] = {0x65 ^ xor, 0x6e ^ xor, 0x74 ^ xor, 0x72 ^ xor, 0x79 ^ xor, 0x70 ^ xor, 0x74 ^ xor, 0x00};
    int len = sizeof(secret) - 1;
    printf("Password: ");
    if (scanf("%63s", input) != 1) {
        return 1;
    }
    if (strlen(input) != len) {
        printf("Wrong.\n");
        return 0;
    }
    int ok = 1;
    for (int i = 0; i < len; i++) {
        if (input[i] != secret[i]) {
            ok = 0;
            break;
        }
    }
    if (ok) {
        printf("Correct. Flag: entrypoint{re_basics}\n");
    } else {
        printf("Wrong.\n");
    }
    return 0;
}