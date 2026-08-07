/* No libc string or memory calls, and built without debug symbols, so cwe_checker
   reports nothing at all. */
int main(int argc, char **argv) {
    (void)argv;
    int total = 0;
    for (int i = 1; i < argc; i++) {
        total += i * 3;
    }
    return total & 0x7f;
}
