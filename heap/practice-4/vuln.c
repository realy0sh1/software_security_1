#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct student
{
    char name[32];
    char rub_id[16];
    int access_level;
    struct student *next;
} student_t;

typedef struct exam_reg
{
    char name[32];
    char rub_id[16];
    int registration_key;
    struct exam_reg *next;
} exam_reg_t;

student_t *head = NULL;
exam_reg_t *heade = NULL;

void read_string(char *buf, size_t size)
{
    if (!fgets(buf, size, stdin))
        exit(1);

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
        buf[len - 1] = '\0';
}

void create_student()
{
    student_t *new_student = malloc(sizeof(student_t));
    if (!new_student)
    {
        puts("Malloc failed!");
        return;
    }

    printf("Name: ");
    read_string(new_student->name, sizeof(new_student->name));

    printf("RUB ID: ");
    read_string(new_student->rub_id, sizeof(new_student->rub_id));

    new_student->access_level = 0;
    new_student->next = head;
    head = new_student;
    printf("Student created at %p\n", new_student);
}

void register_to_exam()
{
    exam_reg_t *new_exam_reg = malloc(sizeof(exam_reg_t));
    if (!new_exam_reg)
    {
        puts("Malloc failed!");
        return;
    }

    printf("Name: ");
    read_string(new_exam_reg->name, sizeof(new_exam_reg->name));

    printf("RUB ID: ");
    read_string(new_exam_reg->rub_id, sizeof(new_exam_reg->rub_id));

    printf("Registration Key: ");
    char key_buf[16];
    read_string(key_buf, sizeof(key_buf));
    new_exam_reg->registration_key = atoi(key_buf);

    new_exam_reg->next = heade;
    heade = new_exam_reg;
    printf("Exam created at %p\n", new_exam_reg);
}

void list_students()
{
    student_t *current = head;
    int idx = 0;

    while (current)
    {
        printf("[%d] %s - %s\n", idx++, current->name, current->rub_id);
        current = current->next;
    }
}

void delete_student()
{
    printf("Index: ");
    char idx_buf[8];
    read_string(idx_buf, sizeof(idx_buf));
    int idx = atoi(idx_buf);

    student_t *current = head;
    student_t *prev = NULL;

    for (int i = 0; i < idx && current; i++)
    {
        prev = current;
        current = current->next;
    }

    if (!current)
    {
        puts("Invalid index!");
        return;
    }

    // UFA vulnerability
    free(current);
    puts("Student deleted!");
}

void secret()
{
    printf("Index: ");
    char idx_buf[8];
    read_string(idx_buf, sizeof(idx_buf));
    int idx = atoi(idx_buf);

    student_t *current = head;
    int i = 0;

    while (current && i < idx)
    {
        current = current->next;
        i++;
    }

    if (!current)
    {
        puts("Invalid index!");
        return;
    }
    // if access_level = 84.874.732
    if ((current->access_level ^ 0xdeadbeef) == 0xdba2ab03)
    {
        system("cat /flag");
        return;
    }
    puts("Access Denied");
    return;
}

void cleanup()
{
    student_t *current = head;
    while (current)
    {
        student_t *next = current->next;
        free(current);
        current = next;
    }
}

int main()
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    puts("Exam Registration System");

    while (1)
    {
        puts("\n1. Create student");
        puts("2. List students");
        puts("3. Delete student");
        puts("4. Register to Exam");
        puts("5. Exit");
        printf("> ");

        char choice[8];
        read_string(choice, sizeof(choice));

        switch (atoi(choice))
        {
        case 1:
            create_student();
            break;
        case 2:
            list_students();
            break;
        case 3:
            delete_student();
            break;
        case 4:
            register_to_exam();
            break;
        case 5:
            cleanup();
            return 0;
        case 42:
            secret();
            break;
        default:
            puts("Invalid choice!");
        }
    }
}
