#include <stdio.h>
#include <stdint.h>

uint32_t mambo_hash(const unsigned char *data, size_t length) {
    uint32_t hash = 0x13579bdfU;

    for (size_t index = 0; index < length; ++index) {
        hash = (hash << 5) | (hash >> 27);
        hash ^= (uint32_t)data[index] + (uint32_t)(index * 0x31U);
        hash += 0x9e3779b9U;
    }
    return hash;
}

void mambo_hash_success(void) {
    puts("Hash accepted!");
}

int main(void) {
    unsigned char key[7];

    if (fgets((char *)key, sizeof(key), stdin) == NULL)
        return 1;
    // guess the key
    if (mambo_hash(key, sizeof(key)) != 0x34999475U) {
        puts ("wrong");
        return 1;
    } else {
        puts("You guessed the password? No way");

        mambo_hash_success();
        return 0;
    }
}
