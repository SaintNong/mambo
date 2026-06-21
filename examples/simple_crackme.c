#include <stddef.h>
#include <unistd.h>

/* Keep this as a distinct symbol so it is an easy symbolic-execution target. */
__attribute__((noinline)) void mambo_success(void) {
    static const char message[] = "Correct Key!\n";
    (void)write(STDOUT_FILENO, message, sizeof(message) - 1);
}

int main(void) {
    char key[5];

    if (read(STDIN_FILENO, key, sizeof(key)) != (ssize_t)sizeof(key))
        return 1;

    if (key[0] != 'M')
        return 1;
    if (key[1] != 'A')
        return 1;
    if (key[2] != 'M')
        return 1;
    if (key[3] != 'B')
        return 1;
    if (key[4] != 'O')
        return 1;

    mambo_success();
    return 0;
}
