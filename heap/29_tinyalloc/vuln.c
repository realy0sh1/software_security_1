#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_ENTRIES 256
static char *entries[MAX_ENTRIES] = { 0 };

static long read_number(const char *prompt)
{
    if (prompt)
        write(STDOUT_FILENO, prompt, strlen(prompt));

    char input[24] = { 0 };
    if (!fgets(input, sizeof(input), stdin))
        return EXIT_SUCCESS;

    char *end = NULL;
    long value = strtol(input, &end, 10);
    if (!value && end && *end != '\0' && *end != '\n')
        errx(EXIT_FAILURE, "'%s' is not a number", input);
    return value;
}

static void read_line(const char *prompt, char *buffer, long size)
{
    if (prompt)
        write(STDOUT_FILENO, prompt, strlen(prompt));

    for (long i = 0; i <= /* oops */ size; ++i) {
        char input = getchar();
        if (input == '\n') {
            buffer[i] = '\0';
            break;
        } else {
            buffer[i] = input;
        }
    }
}

void allocate(void)
{
    long index = read_number("Which index do you want to allocate? ");
    if (index < 0 || index >= MAX_ENTRIES)
        errx(EXIT_FAILURE, "invalid index");
    if (entries[index])
        errx(EXIT_FAILURE, "entry %ld is already occupied", index);

    long size = read_number("How large do you want the entry to be? ");
    entries[index] = malloc(size);
    if (!entries[index])
        err(EXIT_FAILURE, "failed to allocate memory");

    read_line("Enter the contents: ", entries[index], size);
}

void show(void)
{
    long index = read_number("Which index do you want to show? ");
    if (index < 0 || index >= MAX_ENTRIES)
        errx(EXIT_FAILURE, "invalid index");
    if (!entries[index])
        errx(EXIT_FAILURE, "entry %ld is empty", index);
    puts(entries[index]);
}

void deallocate(void)
{
    long index = read_number("Which index do you want to deallocate? ");
    if (index < 0 || index >= MAX_ENTRIES)
        errx(EXIT_FAILURE, "invalid index");
    if (!entries[index])
        errx(EXIT_FAILURE, "entry %ld is empty", index);

    free(entries[index]);
    entries[index] = NULL;
}

int main(void)
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    printf("To test whether the allocator is actually working: malloc is at %p\n", malloc);
    puts("What do you want to do?\n"
         " [1] allocate\n"
         " [2] show\n"
         " [3] deallocate\n"
         " [4] leave\n");

    for (;;) {
        switch (read_number("> ")) {
            case 1: allocate(); break;
            case 2: show(); break;
            case 3: deallocate(); break;
            case 4: return EXIT_SUCCESS;
            default:
                puts("I'm sorry, I don't know what that means.");
                break;
        }
    }
}
