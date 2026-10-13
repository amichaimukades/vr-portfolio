#include <stdio.h>
#include <string.h>

int main(void) {
    char input[64];
    int key = 0x55;
    char secret[] = {0x65 ^ key, 0x6e ^ key, 0x74 ^ key, 0x72 ^ key, 0x79 ^ key, 0x70 ^ key, 0x74 ^ key, 0x00 ^ key};
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
        if ((input[i] ^ key) != secret[i]) {
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