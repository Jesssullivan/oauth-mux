/* Declared ELF fixture: no network, accounts, native stores or tool execution. */
#include <stdio.h>
int main(void) {
    if (puts("OMUX_DIRECT_EXEC_FIXTURE_READY") == EOF || fflush(stdout) != 0)
        return 2;
    return getchar() == 'q' ? 0 : 3;
}
