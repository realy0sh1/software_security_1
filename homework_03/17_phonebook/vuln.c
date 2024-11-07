#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct phonebook_entry {
    char phone_number[32];
    char name[64];
    struct phonebook_entry *next;
    struct phonebook_entry *prev;
};

struct phonebook_entry *phonebook = NULL;

int read_line(char *buffer, size_t size)
{
    // This is normal fgets(), but we remove the newline that it might store in the buffer.
    if (!fgets(buffer, size, stdin))
        return 0;
    // Remove anything starting at the first newline, if any
    char *newline = strchr(buffer, '\n');
    if (newline)
        *newline = '\0';
    return 1;
}

struct phonebook_entry *get_at_index(void)
{
    if (!phonebook) {
        puts("The phonebook is empty.");
        return NULL;
    }

    // Parse the index
    char number_buffer[20];
    printf("Index: ");
    if (!read_line(number_buffer, sizeof(number_buffer))) {
        puts("Failed to read index");
        return NULL;
    }

    if (strlen(number_buffer) <= 0) {
        puts("No index specified");
        return NULL;
    }

    char *number_end = NULL;
    size_t index = (size_t) strtoul(number_buffer, &number_end, 10);
    if (number_end && *number_end != '\0') {
        printf("\"%s\" is not a number\n", number_buffer);
        return NULL;
    }

    // Find the entry
    struct phonebook_entry *entry = phonebook;
    while (index--) {
        entry = entry->next;
        if (!entry) {
            puts("No entry at this index");
            return NULL;
        }
    }

    return entry;
}

int validate_phone_number(char *string)
{
    for (size_t i = 0; i < strlen(string); ++i) {
        char c = string[i];
        if (c == '+' || c == '/' || c == '(' || c == ')' || c == '-' || c == ' ' || (c >= '0' && c <= '9'))
            continue;
        printf("'%c' is not a valid character in a phone number\n", c);
        return 0;
    }
    return 1;
}

void phonebook_list(void)
{
    size_t index = 0;
    if (!phonebook)
        puts("The phone book is empty.");
    else
        for (struct phonebook_entry *entry = phonebook; entry != NULL; (entry = entry->next), ++index)
            printf("[%3zu] %-16s %s\n", index, entry->phone_number, entry->name);
}

void phonebook_show(void)
{
    struct phonebook_entry *entry = get_at_index();
    if (!entry)
        return;
    printf("Phone number: %-16s\nName: %s\n", entry->phone_number, entry->name);
}

void phonebook_add(void)
{
    struct phonebook_entry *new_entry = calloc(1, sizeof(*new_entry));
    if (!new_entry)
        goto error;

    printf("Phone number: ");
    if (!read_line(new_entry->phone_number, sizeof(new_entry->phone_number)))
        goto error;
    if (!validate_phone_number(new_entry->phone_number))
        goto error;

    printf("Name: ");
    if (!read_line(new_entry->name, sizeof(new_entry->name)))
        goto error;

    new_entry->next = phonebook;
    new_entry->prev = NULL;
    if (phonebook)
        phonebook->prev = new_entry;
    phonebook = new_entry;
    return;

error:
    if (new_entry)
        free(new_entry);
    puts("Failed to create entry");
}

void phonebook_edit(void)
{
    struct phonebook_entry *entry = get_at_index();
    if (!entry)
        return;

    printf("Phone number: ");
    char phone_number[32];
    if (!read_line(phone_number, sizeof(phone_number)))
        goto error;
    if (!validate_phone_number(phone_number))
        goto error;

    printf("Name: ");
    char name[80];
    if (!read_line(name, sizeof(name)))
        goto error;

    memcpy(entry->phone_number, phone_number, sizeof(phone_number));
    memcpy(entry->name, name, sizeof(name));
    return;

error:
    puts("Failed to update entry");
}

void phonebook_delete(void)
{
    struct phonebook_entry *entry = get_at_index();
    if (!entry)
        return;

    // Update linked list
    if (entry->prev)
        entry->prev->next = entry->next;
    else
        phonebook = entry->next;
    if (entry->next)
        entry->next->prev = entry->prev;

    // Get rid of the actual entry
    free(entry);
}

int main(void)
{
    char command[20];
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    printf("Welcome to the softsec phonebook service. Your phone number is %+ld\n",
           (long) command);

    for (;;) {
        printf("You can\n"
               " - [L]ist phonebook entries\n"
               " - [A]dd a phonebook entry\n"
               " - [E]dit a phonebook entry\n"
               " - [D]elete a phonebook entry\n"
               " - [S]how a phonebook entry\n"
               " - [Q]uit\n"
               "> ");

        // Read the command from user input
        if (!read_line(command, sizeof(command)))
            break;

        // Find out what that command means
        if (!strcasecmp(command, "L"))
            phonebook_list();
        else if (!strcasecmp(command, "A"))
            phonebook_add();
        else if (!strcasecmp(command, "E"))
            phonebook_edit();
        else if (!strcasecmp(command, "D"))
            phonebook_delete();
        else if (!strcasecmp(command, "S"))
            phonebook_show();
        else if (!strcasecmp(command, "Q"))
            break;
        else
            printf("I'm sorry, I'm not sure what \"%s\" means...\n", command);
    }
}
