#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NOTES 16
#define NOTE_SIZE 256

char *notes[MAX_NOTES] = { 0 };

static void read_line(const char *restrict prompt, char *restrict into, size_t size)
{
    if (prompt)
        printf("%s", prompt);
    if (!fgets(into, size, stdin))
        err(EXIT_FAILURE, "failed to read input");
    char *newline = strrchr(into, '\n');
    if (newline)
        *newline = '\0';
}

static int read_number(const char *prompt)
{
    if (prompt)
        printf("%s", prompt);
    int value = 0;
    if (scanf("%d", &value) != 1)
        errx(EXIT_FAILURE, "input is not a number");
    for (char discard = getchar(); discard != '\n';)
        errx(EXIT_FAILURE, "unexpected character after number: '%c'", discard);
    return value;
}

static int read_index(const char *prompt)
{
    int index = read_number(prompt);
    if (index < 0 || index >= MAX_NOTES)
        errx(EXIT_FAILURE, "%d is not a valid note index", index);
    return index;
}

static void add_note(void)
{
    int index = read_index("Enter note index: ");
    if (notes[index])
        return (void) printf("Note %d is already in use.\n", index);
    notes[index] = malloc(NOTE_SIZE);
    read_line("Enter note: ", notes[index], NOTE_SIZE);
}

static void delete_note(void)
{
    int index = read_index("Enter note index: ");
    free(notes[index]);
}

static void edit_note(void)
{
    int index = read_index("Enter note index: ");
    if (!notes[index])
        return (void) printf("Note %d does not exist.\n", index);
    read_line("Enter note: ", notes[index], NOTE_SIZE);
}

static void show_note(void)
{
    int index = read_index("Enter note index: ");
    if (notes[index])
        printf("Note %d: %s\n", index, notes[index]);
    else
        printf("Note %d does not exist.\n", index);
}

int main(void)
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    puts("[A]dd | [D]elete | [E]dit | [S]how | E[x]it");
    printf("This may be helpful: %p\n", __builtin_frame_address(0));
    for (;;) {
        char command[24] = { 0 };
        read_line("> ", command, sizeof(command));
        switch (command[0]) {
            case 'a': case 'A': puts("Adding note..."); add_note(); break;
            case 'd': case 'D': puts("Deleting note..."); delete_note(); break;
            case 'e': case 'E': puts("Editing note..."); edit_note(); break;
            case 's': case 'S': puts("Showing note..."); show_note(); break;
            case 'x': case 'X': puts("Goodbye..."); return EXIT_SUCCESS;
            default: printf("I don't know what '%c' means\n", command[0]); break;
        }
    }
}
