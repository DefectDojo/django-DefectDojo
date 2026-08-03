#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void copy_name(char *dest, const char *src) {
    strcpy(dest, src);
}

void read_input(void) {
    char buffer[64];
    gets(buffer);
    printf(buffer);
}

int random_token(void) {
    return rand();
}
