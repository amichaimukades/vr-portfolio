#include <stdio.h>
#include <string.h>

void greet(void) {
    char name[100];
    printf("Name: ");
    fgets(name, sizeof(name), stdin);
    printf("Hello, %s\n", name);
}

int main(void) {
    greet();
    return 0;
}