#include <stdio.h>
#include <string.h>

void greet(void) {
    char first_name[30];
    char last_name[20];
    printf("First Name: ");
    fgets(first_name, sizeof(first_name), stdin);
    printf("Last Name: ");
    fgets(last_name, sizeof(last_name), stdin);
    printf("Hello, %s %s\n", first_name, last_name);
}

int main(void) {
    greet();
    return 0;
}