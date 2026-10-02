#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void leaks(void) {
    char *buffer = malloc(128);
    strcpy(buffer, "data");
}

void out_of_bounds(void) {
    int values[4];
    values[4] = 1;
}

int uninitialised(void) {
    int total;
    return total + 1;
}

void null_deref(void) {
    char *pointer = NULL;
    *pointer = 'x';
}
