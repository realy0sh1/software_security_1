#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#define SCOUTER_DIGITS 0x4
#define MAX_INPUT 0x10

__attribute__((force_align_arg_pointer)) 
void its_over_9000(void)
{
    printf("Vegeta: IT'S OVER 9000!!!\n");
    printf("Nappa: WHAT?! 9000?! There's no way that can be right!\n");
    printf("*Vegeta crushes his scouter*\n");
    system("cat /flag");
}

void measure_power_level(int scouter_capacity) {
    char power_level[SCOUTER_DIGITS];
    printf("Vegeta: Let's see what Kakarot's power level is with this new scouter.\n");
    fgets(power_level, scouter_capacity - 1, stdin);
    printf("Vegeta: Hmph! It's only %s\n", power_level);
}

int main(void)
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    char scouter_input[MAX_INPUT];
    int scouter_capacity;

    printf("Nappa: Hey Vegeta, how many digits can your new scouter display?\n");
    fgets(scouter_input, sizeof(scouter_input), stdin);

    scouter_capacity = atoi(scouter_input);
    if (scouter_capacity <= SCOUTER_DIGITS) {
        measure_power_level(scouter_capacity);
    } else {
        printf("Vegeta: Don't be absurd, Nappa! A scouter with that many digits?\n");
        printf("Vegeta: Use your head for once! No warrior could have a power level that high.\n");
        printf("Vegeta: Now stop wasting time and let's find Kakarot!\n");
    }

    return 0;
}
