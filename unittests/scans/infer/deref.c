#include <stdlib.h>

int main(void) {
    int *values = malloc(sizeof(int) * 2);
    values[0] = 7;
    free(values);
    return 0;
}
