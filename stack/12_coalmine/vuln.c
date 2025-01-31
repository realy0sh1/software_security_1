#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    for (;;) {
        puts("Welcome to the coal mine. What do you want to do?\n (1) Go mining\n (2) Leave");
        char input[20] = { 0 };
        if (!fgets(input, sizeof(input), stdin))
            err(EXIT_FAILURE, "fgets");
        int command = atoi(input);
        switch (command) {
            case 1: {
                /* Go mining */
                pid_t pid = fork();
                if (pid < 0) {
                    err(EXIT_FAILURE, "fork");
                } else if (pid == 0) {
                    printf("What do you want to mine? ");
                    memset(input, 0, sizeof(input));
                    if (read(STDIN_FILENO, input, 0x100) < 0)
                        err(EXIT_FAILURE, "read");
                    for (size_t i = 0; i < sizeof(input); ++i)
                        if (input[i] == '\n')
                            input[i] = '\0';
                    printf("You mine all the %.20s you can and prepare to leave\n", input);
                    return EXIT_SUCCESS;
                } else {
                    int status;
                    if (waitpid(pid, &status, __WALL) != pid)
                        err(EXIT_FAILURE, "waitpid");
                    if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
                        puts("Sadly, the mine caved in :(");
                    else
                        puts("You made it back alive :)\n");
                }
                break;
            }
            case 2:
                /* Leave */
                puts("Bye!");
                return EXIT_SUCCESS;
            default:
                printf("I don't know what \"%s\" means, sorry\n", input);
                break;
        }
    }
}
