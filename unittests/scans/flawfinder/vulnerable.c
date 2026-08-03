#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char buf[16];
    strcpy(buf, argv[1]);
    printf(buf);
    gets(buf);
    return 0;
}
