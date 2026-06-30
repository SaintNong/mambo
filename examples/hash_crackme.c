#include <stdint.h>
#include <unistd.h>

/*
 * A small, deliberately non-cryptographic hash. Its loop, index mixing,
 * rotation, XOR, and modular addition exercise Mambo's symbolic CPU model.
 */
__attribute__((noinline)) uint32_t mambo_hash(const unsigned char *data, size_t length) {
    uint32_t hash = 0x13579bdfU;

    for (size_t index = 0; index < length; ++index) {
        hash = (hash << 5) | (hash >> 27);
        hash ^= (uint32_t)data[index] + (uint32_t)(index * 0x31U);
        hash += 0x9e3779b9U;
    }
    return hash;
}

__attribute__((noinline)) void mambo_hash_success(void) {
    static const char message[] = "Hash accepted!\n";
    (void)write(STDOUT_FILENO, message, sizeof(message) - 1);
}

int main(void) {
    unsigned char key[6];

    if (read(STDIN_FILENO, key, sizeof(key)) != (ssize_t)sizeof(key))
        return 1;
    /* Hash of the intentionally undisclosed six-byte key. */
    if (mambo_hash(key, sizeof(key)) != 0x34999475U)
        return 1;

    mambo_hash_success();
    return 0;
}
