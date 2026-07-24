#include <stdio.h>

void mambo_stream_success(void) {
    puts("Stream accepted!");
}

int main(void) {
    char key[6];
    FILE *stream;

    fflush(stdout);
    stream = stdin;
    if (fgets(key, sizeof(key), stream) == NULL)
        return 1;

    if (key[0] != 'M' || key[1] != 'A' || key[2] != 'M' ||
        key[3] != 'B' || key[4] != 'O')
        return 1;

    mambo_stream_success();
    return 0;
}
