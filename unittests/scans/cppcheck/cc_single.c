#include <stdio.h>

int main(void) {
    int values[10];
    for (int i = 0; i < 10; i++) {
        values[i] = i;
    }
    printf("%d\n", values[10]);
    return 0;
}
