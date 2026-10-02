#include <stdlib.h>
#include <string.h>

int leaked_allocation(void) {
    int *values = malloc(sizeof(int) * 4);
    values[0] = 1;
    return values[0];
}

int null_dereference(int flag) {
    int *values = NULL;
    if (flag) {
        values = malloc(sizeof(int));
    }
    return *values;
}

int use_after_release(void) {
    char *block = malloc(16);
    free(block);
    return block[0];
}

int uninitialised_read(void) {
    int value;
    return value + 1;
}

int main(void) {
    return leaked_allocation() + null_dereference(0) + use_after_release() + uninitialised_read();
}
