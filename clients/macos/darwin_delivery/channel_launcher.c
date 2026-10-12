/* Experimental signed channel boundary. No PATH/shell or service/vault calls.
 * Compile every role with the declared immutable instance/role/backend macros.
 * A browser manifest selects this executable; it never supplies environment.
 */
#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef OMUX_BIND_INSTANCE
#error "Declared channel binding is required"
#endif
#ifndef OMUX_BIND_ROLE
#error "Declared role is required"
#endif
#ifndef OMUX_BIND_BACKEND
#error "Declared backend is required"
#endif

static const volatile char binding[] __attribute__((used)) = "OMUX_CHANNEL_BINDING_V1:"
    OMUX_BIND_INSTANCE ":" OMUX_BIND_ROLE ":" OMUX_BIND_BACKEND;

static int refuse(void) {
    static const char message[] = "Omux channel entrypoint could not start its declared backend.\n";
    (void)write(STDERR_FILENO, message, sizeof(message) - 1);
    return 126;
}

int main(int argc, char **argv) {
    unsigned char observed = 0;
    /* Volatile reads retain the complete public marker through optimization;
     * byte inspection alone still cannot authenticate a compiler invocation. */
    for (size_t index = 0; index < sizeof(binding) - 1; ++index) observed |= (unsigned char)binding[index];
    if (argc < 1 || !observed || binding[0] != 'O' ||
        (strcmp(OMUX_BIND_INSTANCE, "dev") && strcmp(OMUX_BIND_INSTANCE, "default"))) return refuse();
    char selected[PATH_MAX], actual[PATH_MAX], backend[PATH_MAX];
    uint32_t size = sizeof(selected);
    if (_NSGetExecutablePath(selected, &size) != 0 || !realpath(selected, actual)) return refuse();
    char *slash = strrchr(actual, '/');
    if (!slash || strcmp(slash + 1, OMUX_BIND_ROLE) != 0) return refuse();
    *slash = '\0';
    const size_t directory = strlen(actual), leaf = strlen(OMUX_BIND_BACKEND);
    if (directory + 1 + leaf + 1 > sizeof(backend)) return refuse();
    memcpy(backend, actual, directory);
    backend[directory] = '/';
    memcpy(backend + directory + 1, OMUX_BIND_BACKEND, leaf + 1);
    /* This immutable binding wins over browser/login/application inheritance.
     * No arbitrary socket may redirect the signed normal controls boundary. */
    if (setenv("OMUX_INSTANCE", OMUX_BIND_INSTANCE, 1) != 0 || unsetenv("OMUX_SOCKET") != 0) return refuse();
    argv[0] = (char *)OMUX_BIND_ROLE;
    execv(backend, argv);
    return refuse();
}
