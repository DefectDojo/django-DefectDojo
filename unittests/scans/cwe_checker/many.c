#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void dangerous_copy(const char *src) {
    char buffer[16];
    strcpy(buffer, src);
    printf(buffer);
}

void double_release(void) {
    char *block = malloc(64);
    strcpy(block, "payload");
    free(block);
    free(block);
}

void use_after_release(void) {
    char *block = malloc(32);
    free(block);
    strcpy(block, "late");
}

void unchecked_allocation(size_t count) {
    int *values = malloc(count * sizeof(int));
    values[0] = 1;
    free(values);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        dangerous_copy(argv[1]);
    }
    double_release();
    use_after_release();
    unchecked_allocation(4);
    return 0;
}
