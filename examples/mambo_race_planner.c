#include <stdint.h>
#include <stdio.h>

void mambo_license_success(void) {
    puts("Mambo license activated!");
}

void welcome_msg(void) {
    puts("==============================");
    puts("= Welcome to Mambo Enterprise =");
    puts("==============================");
    puts("\nMambo, Mambo! Omatsuri, Mambo!");
}

static int race_pace_planner(void) {
    unsigned int distance;
    unsigned int minutes;
    unsigned int seconds;
    unsigned int total_seconds;
    unsigned int pace_hundredths;
    unsigned int speed_hundredths;

    puts("\nTwinkle Series Race Pace Planner");
    printf("Race distance in metres: ");
    if (scanf("%u", &distance) != 1)
        return 1;

    printf("Target time (minutes seconds): ");
    if (scanf("%u %u", &minutes, &seconds) != 2)
        return 1;
    if (distance == 0 || seconds >= 60)
        return 1;

    total_seconds = minutes * 60U + seconds;
    if (total_seconds == 0)
        return 1;

    pace_hundredths = total_seconds * 100U * 200U / distance;
    speed_hundredths = distance * 360U / total_seconds;

    printf(
        "Target pace: %u.%02u seconds per 200m\n",
        pace_hundredths / 100U,
        pace_hundredths % 100U
    );
    printf(
        "Average speed: %u.%02u km/h\n",
        speed_hundredths / 100U,
        speed_hundredths % 100U
    );
    return 0;
}

int main(void) {
    char key[18];
    uint32_t accumulator;
    uint32_t checksum;
    uint32_t instruction;
    uint32_t check0;
    uint32_t check1;

    welcome_msg();
    printf("\nEnter your Mambo license key: ");
    if (fgets(key, sizeof(key), stdin) == NULL)
        goto rejected;

    /*
     * Mambo Race Planner keys encode four training modules:
     * S = speed, T = stamina, P = power, G = guts.
     * Each module is followed by its training level.
    */
    if (key[0] != 'M')
        goto rejected;
    if (key[1] != 'A')
        goto rejected;
    if (key[2] != 'M')
        goto rejected;
    if (key[3] != 'B')
        goto rejected;
    if (key[4] != 'O')
        goto rejected;
    if (key[5] != '-')
        goto rejected;
    if (key[14] != '-')
        goto rejected;

    accumulator = 0x13579bdfU;
    checksum = 0x4d414d42U;

    for (instruction = 0; instruction < 4; ++instruction) {
        unsigned char module = (unsigned char)key[6 + instruction * 2];
        unsigned char encoded_level = (unsigned char)key[7 + instruction * 2];
        uint32_t level;

        if (encoded_level < '0')
            goto rejected;
        if (encoded_level > '9')
            goto rejected;
        level = (uint32_t)(encoded_level - '0');

        checksum = (checksum << 5) | (checksum >> 27);
        checksum ^= (uint32_t)module;
        checksum += level;

        if (module == 'S') {
            accumulator += level;
        } else if (module == 'T') {
            accumulator ^= level;
        } else if (module == 'P') {
            level += 1U;
            accumulator *= level;
        } else if (module == 'G') {
            accumulator = (accumulator << 3) | (accumulator >> 29);
            accumulator ^= level;
        } else {
            goto rejected;
        }
    }

    /* This signature represents a Team Canopus-approved training plan. */
    if (accumulator != 0x6af37c2cU)
        goto rejected;

    check0 = (checksum ^ accumulator) & 15U;
    check1 = ((checksum >> 4) ^ (accumulator >> 8)) & 15U;

    if ((uint32_t)(unsigned char)key[15] != (uint32_t)'A' + check0)
        goto rejected;
    if ((uint32_t)(unsigned char)key[16] != (uint32_t)'A' + check1)
        goto rejected;

    mambo_license_success();
    return race_pace_planner();

rejected:
    puts("\nLicense rejected: that key is not registered with Mambo Enterprise.");
    puts("Please check the key and try again.");
    return 1;
}
