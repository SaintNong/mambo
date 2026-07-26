#include <stdio.h>

void mambo_if_success(void) {
    puts("you did it");
}

void trap_func(void) {
    puts("not correct");
    puts("you are wrong");
}

int main(void) {
    char key[4];

    if (fgets(key, sizeof(key), stdin) == NULL)
        return 1;

    // dead end path
    if (key[0] == 'X') {
        if (key[1] == 'X') {
            if (key[2] == 'X')
                return 1; // wrong
        }
    }

    // dead end path #2
    if (key[0] == 'C') {
        if (key[1] == 'A') {
            if (key[2] == 'N')
                return 1; // wrong
            
            if (key[2] == 'T')
                trap_func(); // wrong
        }
    }

    // correct path 2
    if (key[0] == 'M') {
        if (key[1] == 'A') {
            // goal
            if (key[2] == 'P')
                mambo_if_success();
        }
    }

    return 0;
}
