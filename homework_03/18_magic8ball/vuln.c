#include <err.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

const char *responses[] = {
    "Reply hazy, try again.",
    "Ask again later.",
    "Better not tell you now.",
    "Cannot predict now.",
    "Concentrate and ask again.",
};

const char *randomized_response(void)
{
    return responses[rand() % (sizeof(responses) / sizeof(responses[0]))];
}

int main(void)
{
    srand(time(NULL)); // Do _not_ do this at home please, this is terrible randomness.

    struct {
        char question[40];
        const char * (*get_response)(void);
    } ball = {
        .question = { 0 },
        .get_response = randomized_response
    };

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    printf("Feel free to ask the Magic ~~8~~ %ju Ball anything.\nYour question: ", (uintmax_t) rand);

    if (read(STDIN_FILENO, ball.question, 400) < 0)
        err(EXIT_FAILURE, "That's not a question...");

    puts("...");
    puts(ball.get_response());
}
