/* Exactly one dangerous call, and built without debug symbols, so cwe_checker
   reports a single CWE676 warning. */
#include <string.h>

static char buffer[32];

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }
    strcpy(buffer, argv[1]);
    return buffer[0];
}
