#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define MAX_INVENTORY 0x5
#define MAX_NAME 0x10
#define MAX_EQUIPMENT_NAME 0x60

typedef struct
{
    char name[MAX_NAME];
    char surname[MAX_NAME];
} ghostbuster_t;

typedef struct
{
    char name[MAX_EQUIPMENT_NAME];
} equipment_t;

void clear_input_buffer()
{
    char c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void safe_read(char *buf, size_t size)
{
    size_t len;
    if (fgets(buf, size, stdin) == NULL)
    {
        puts("reading failed");
        _Exit(EXIT_FAILURE);
    }
    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
    {
        buf[len - 1] = '\0';
    }
}

void view(size_t *equipment_list)
{
    puts("\n=== EQUIPMENT LIST ===");

    for (int i = 0; i < MAX_INVENTORY; i++)
    {
        if (equipment_list[i] == 0)
        {
            printf("Equipment %d | ID: 0 | Name: Empty\n", i + 1);
            continue;
        }
        printf("Equipment %d | ID: %lu | Name: %s\n", i + 1, equipment_list[i], ((equipment_t *)equipment_list[i])->name);
    }
}

void delete(size_t *equipment_list)
{
    size_t id;

    view(equipment_list);

    puts("\n=== DELETE EQUIPMENT ===");
    puts("Enter equipment ID to delete:");
    scanf("%lu%*c", &id);
    free((equipment_t *)id);

    size_t i = 0;
    for (; i < MAX_INVENTORY; i++) {
        if (equipment_list[i] == id) {
            equipment_list[i] = 0;
            return;
        }
    }
    if (i == MAX_INVENTORY)
    {
        puts("Equipment not found");
        return;
    }
}

void add(size_t *equipment_list)
{
    equipment_t *new_equip = malloc(sizeof(equipment_t));

    puts("\n=== ADD EQUIPMENT ===");

    printf("New equipment ID: %lu\n", new_equip);

    puts("Enter equipment name:");
    safe_read(new_equip->name, MAX_EQUIPMENT_NAME);

    for (int i = 0; i < MAX_INVENTORY; i++)
    {
        if (equipment_list[i] == 0)
        {
            equipment_list[i] = (size_t)new_equip;
            return;
        }
    }
    puts("Your inventory is full");
}

void update(size_t *equipment_list)
{
    size_t id;
    equipment_t *current_equip;

    view(equipment_list);

    puts("\n=== UPDATE EQUIPMENT ===");
    puts("Enter equipment ID:");
    scanf("%lu%*c", &id);

    size_t i = 0;
    for (; i < MAX_INVENTORY; i++) {
        if (equipment_list[i] == id) {
            break;
        }
    }
    if (i == MAX_INVENTORY)
    {
        puts("Equipment not found");
        return;
    }

    current_equip = (equipment_t *)id;

    puts("Enter new equipment name:");
    safe_read(current_equip->name, MAX_EQUIPMENT_NAME);

    puts("Equipment updated");
}

void ghostbuster_info(ghostbuster_t *operator)
{
    char choice;

    puts("\n=== GHOSTBUSTER PERSONNEL FILE ===");
    printf("Name: %s\n", operator->name);
    printf("Surname: %s\n", operator->surname);

    puts("Do you want to update your profile? [y/n]");

    choice = getchar();
    clear_input_buffer();

    if (choice == 'y')
    {
        puts("Enter your new name:");
        safe_read(operator->name, MAX_NAME);

        puts("Enter your new surname:");
        safe_read(operator->surname, MAX_NAME);
    }
}

int main(void)
{
    char command;
    ghostbuster_t operator= {0};
    size_t equipment_list[MAX_INVENTORY] = {0};

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    puts("=== GHOSTBUSTERS EQUIPMENT MANAGEMENT SYSTEM ===\n");
    printf("Operator ID: %lu\n", &operator.surname);
    printf("Target Location: \"The House of the Spirits\" | Paranormal Level: %lu\n", kill);

    strcpy(operator.surname, "Stantz");

    puts("\n=== SYSTEM READY FOR OPERATION ===");
    while (1)
    {
        puts("[a]dd to loadout");
        puts("[v]iew loadout");
        puts("[u]pdate loadout");
        puts("[d]elete from loadout");
        puts("[g]hostbuster profile");
        puts("[e]nd session");

        command = getchar();
        clear_input_buffer();
        switch (command)
        {
        case 'a':
            add(equipment_list);
            break;
        case 'v':
            view(equipment_list);
            break;
        case 'u':
            update(equipment_list);
            break;
        case 'd':
            delete (equipment_list);
            break;
        case 'g':
            ghostbuster_info(&operator);
            break;
        case 'e':
            puts("Shutting down equipment management system...");
            return 0;
        default:
            puts("ERROR: Invalid command");
        }
        puts("\n=== READY FOR NEXT OPERATION ===");
    }
}
