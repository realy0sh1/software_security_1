#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX_WARRIOR_SIZE 1024
#define MIN_WARRIOR_SIZE 128 /* you must be at least _this tall_ to ride */
#define MAX_WARRIOR_COUNT 256

static char *warriors[MAX_WARRIOR_COUNT] = { 0 };
static int warrior_count = 0;

void read_line(char *buffer, size_t size)
{
    errno = 0;
    if (fgets(buffer, size, stdin)) {
        size_t length = strlen(buffer);
        while (length && buffer[length - 1] == '\n')
            buffer[--length] = '\0';
        return;
    }
    if (errno)
        err(EXIT_FAILURE, "failed to read input");
    errx(EXIT_FAILURE, "no input");
}

int read_number(void)
{
    char input[20] = { 0 };
    read_line(input, sizeof(input));

    char *end = NULL;
    errno = 0;
    long value = strtol(input, &end, 10);
    if (!value && errno)
        err(EXIT_FAILURE, "'%s' is not a number", input);
    if (end && *end)
        errx(EXIT_FAILURE, "'%s' is not a number", input);
    if (value < INT_MIN || INT_MAX < value)
        errx(EXIT_FAILURE, "%ld is out of range", value);
    return (int) value;
}

int read_size(void)
{
    printf("Enter size: ");
    int size = read_number();
    if (size < MIN_WARRIOR_SIZE || size >= MAX_WARRIOR_SIZE)
        errx(EXIT_FAILURE, "bad warrior size: %d", size);
    return size;
}

int find_warrior(void)
{
    char matching[MAX_WARRIOR_SIZE];
    printf("Enter part of the name: ");
    read_line(matching, sizeof(matching));

    for (int i = 0; i < warrior_count; ++i)
        if (strstr(warriors[i], matching))
            return i;
    errx(EXIT_FAILURE, "no warrior by that name");
}

void create_warrior(void)
{
    if (warrior_count >= MAX_WARRIOR_COUNT)
        errx(EXIT_FAILURE, "too many warriors");

    int size = read_size();
    char *buffer = malloc(size);
    if (!buffer)
        err(EXIT_FAILURE, "failed to allocate memory");
    printf("Enter name: ");
    read_line(buffer, size);

    warriors[warrior_count++] = buffer;
}

void inspect_warrior(void)
{
    int index = find_warrior();
    int size = read_size();
    printf("Warrior ");
    write(STDOUT_FILENO, warriors[index], size);
    printf(" is currently at position %d\n", index + 1);
}

void rename_warrior(void)
{
    int index = find_warrior();
    size_t length = strlen(warriors[index]) + 2; // + 1 for \n (stripped by read_line) + 1 for \0
    printf("Enter new name: ");
    read_line(warriors[index], length);
}

void delete_warrior(void)
{
    int index = find_warrior();
    char *buffer = warriors[index];
    if (index != warrior_count - 1)
        warriors[index] = warriors[warrior_count - 1];
    --warrior_count;
    printf("Welcome to Odin's court, ");
    puts(buffer);
    free(buffer);
}

int main(void)
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    puts("You can\n"
         " [1] create a warrior\n"
         " [2] inspect a warrior\n"
         " [3] rename a warrior\n"
         " [4] send a warrior to Valhalla\n"
         " [5] end the world\n");

    for (;;) {
        printf("> ");
        switch (read_number()) {
            case 1: create_warrior(); break;
            case 2: inspect_warrior(); break;
            case 3: rename_warrior(); break;
            case 4: delete_warrior(); break;
            case 5: return EXIT_SUCCESS;
            default: puts("I don't know what that means..."); break;
        }
    }
}
