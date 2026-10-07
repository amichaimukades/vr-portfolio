#include <stdio.h>
#include <string.h>

int main(void) {
    char input[64];
    char secret[] = {0x65, 0x6e, 0x74, 0x72, 0x79, 0x70, 0x74, 0x00};
    printf("Password: ");
    if (scanf("%63s", input) != 1) {
        return 1;
    }
    if (strcmp(input, secret) == 0) {
        printf("Correct. Flag: entrypoint{re_basics}\n");
    } else {
        printf("Wrong.\n");
    }
    return 0;
}