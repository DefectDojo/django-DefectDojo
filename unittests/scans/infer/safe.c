#include <stdlib.h>

int sum_pair(const int *values) {
    if (values == NULL) {
        return 0;
    }
    return values[0] + values[1];
}

int main(void) {
    int pair[2] = {1, 2};
    return sum_pair(pair);
}
