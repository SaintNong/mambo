#include <stdio.h>

void mambo_success(void) {
    puts("Correct Key!");
}

int main(void) {
    char key[6];

    if (fgets(key, sizeof(key), stdin) == NULL)
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
