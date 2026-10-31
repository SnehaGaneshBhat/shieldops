#include <stdio.h>
int add(int a, int b) { return a + b; }
int greet(const char *name) {
    printf("Hello, %s!\n", name);
    return 0;
}
int main(void) {
    greet("BuildGuard");
    printf("2+3=%d\n", add(2, 3));
    return 0;
}
