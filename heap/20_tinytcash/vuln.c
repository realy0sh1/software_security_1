#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <unistd.h>

typedef struct {
    char *name;
    char *log;
    uint8_t log_length;
    uint64_t balance;
    bool active;
} account_t;

typedef struct accounts {
    account_t *self;
    struct accounts *next;
} accounts_t;

typedef enum {
    EVT_DEPOSIT = 2,
    EVT_WITHDRAW = 3,
    EVT_TRANSFER_OUT = 4,
    EVT_TRANSFER_IN = 5,
} event_t;

#define NAME_LENGTH 8
#define LOG_LENGTH 0x40

static void read_name(char *into)
{
    for (size_t i = 0; i < NAME_LENGTH; ++i) {
        int t = getchar();
        if (t == EOF)
            errx(EXIT_FAILURE, "failed to read byte from stdin - has it been closed?");
        into[i] = t;
    }
    getchar();
}

static void log_event(account_t *acct, event_t event, void *data, size_t data_length)
{
    if (data_length >= LOG_LENGTH)
        errx(EXIT_FAILURE, "log entry is too long");

    unsigned space_after_new_entry = LOG_LENGTH - (data_length + 1);
    unsigned bytes_to_keep = acct->log_length < space_after_new_entry
                           ? acct->log_length
                           : space_after_new_entry;
    if (bytes_to_keep)
        memmove(acct->log + data_length + 1, acct->log, bytes_to_keep);
    memcpy(acct->log, data, data_length);
    acct->log[data_length] = event;

    acct->log_length = bytes_to_keep + data_length + 1;
}

accounts_t *create(accounts_t *head)
{
    accounts_t *entry = malloc(sizeof(*entry));
    if (!entry)
        err(EXIT_FAILURE, "failed to allocate list entry");

    entry->self = malloc(sizeof(*entry->self));
    if (!entry->self)
        err(EXIT_FAILURE, "failed to allocate account");
    

    // LOG_LENGTH = 0x40 = 64 (can be from tcache)
    entry->self->log = malloc(LOG_LENGTH);
    if (!entry->self->log)
        err(EXIT_FAILURE, "failed to allocate log");

    entry->self->name = malloc(NAME_LENGTH);
    if (!entry->self->name)
        err(EXIT_FAILURE, "failed to allocate name");

    entry->self->log_length = 0;
    entry->self->active = true;
    entry->self->balance = 0;
    entry->next = head;

    printf("CREATE\n");

    printf("What is the account identifier (%u bytes long)?\n", NAME_LENGTH);
    read_name(entry->self->name);

    return entry;
}

accounts_t *deposit(accounts_t *head)
{
    printf("DEPOSIT\n");

    char name[NAME_LENGTH];
    printf("What account should I deposit funds into?\n");
    read_name(name);

    for (accounts_t *e = head; e; e = e->next) {
        if (memcmp(e->self->name, name, NAME_LENGTH) == 0) {
            printf("How much money should I deposit in this account?\n");
            uint64_t deposit = 0;
            scanf("%" PRIu64, &deposit);
            getchar(); /* newline */

            e->self->balance += deposit;
            printf("Deposited %" PRIu64 " into account %s, total is now %" PRIu64 "\n", deposit,
                   e->self->name, e->self->balance);

            log_event(e->self, EVT_DEPOSIT, &deposit, sizeof(deposit));

            return head;
        }
    }

    printf("Account does not exist\n");
    return head;
}

// widthdraw free()'s log when 0 balance, but pointer remains and can be reused
// => use after free
accounts_t *withdraw(accounts_t *head)
{
    printf("WITHDRAW\n");

    char name[NAME_LENGTH];
    printf("What account should I withdraw funds from?\n");
    read_name(name);

    for (accounts_t *e = head; e; e = e->next) {
        if (memcmp(e->self->name, name, NAME_LENGTH) == 0) {
            printf("How much money should I withdraw from this account?\n");
            uint64_t withdraw  = 0;
            scanf("%" PRIu64, &withdraw);
            getchar(); /* newline */

            if (withdraw > e->self->balance) {
                printf("Unable to withdraw %" PRIu64 " from account %s, total is %" PRIu64 "\n",
                       withdraw, e->self->name, e->self->balance);
                return head;
            }

            e->self->balance -= withdraw;
            printf("Withdrew %" PRIu64 " from account %s, total is now %" PRIu64 "\n", withdraw,
                   e->self->name, e->self->balance);

            log_event(e->self, EVT_WITHDRAW, &withdraw, sizeof(withdraw));

            if (e->self->balance == 0) {
                printf("Account has no remaining balance, closing it\n");
                // free log, but do not delete pointer, so can be used later
                free(e->self->log);
                // log is used a malloc()'ed char array
                // free()'d chunk is now in tcache
                // so we have next pointer as first entry and key as second
                // no pointer mangeling, so we can just override the next pointer
                // tcache nows how many elements in linked list so free() 2 logs
                // then we can override the next pointer of 2nd free()'d log, as
                // this log is the head
                // alloc and ignore
                // alloc again and now it returns value of our choice (write into log first via deposit)
                e->self->log_length = 0;
                e->self->active = false;
            }
            return head;
        }
    }

    printf("Account does not exist\n");
    return head;
}

accounts_t *transfer(accounts_t *head)
{
    printf("TRANSFER\n");

    char from[NAME_LENGTH];
    printf("What account should I transfer from?\n");
    read_name(from);

    char to[NAME_LENGTH];
    printf("What account should I transfer to?\n");
    read_name(to);

    account_t *from_acct = NULL, *to_acct = NULL;
    for (accounts_t *e = head; e && (!from_acct || !to_acct); e = e->next) {
        if (memcmp(e->self->name, from, NAME_LENGTH) == 0 && !from_acct)
            from_acct = e->self;
        else if (memcmp(e->self->name, to, NAME_LENGTH) == 0 && !to_acct)
            to_acct = e->self;
    }

    if (!from_acct || !to_acct) {
        printf("Account not found\n");
        return head;
    }

    uint64_t transfer = 0;
    printf("How much should I transfer?\n");
    scanf("%" PRIu64, &transfer);
    getchar(); /* newline */

    if (transfer > from_acct->balance) {
        printf("Unable to withdraw %" PRIu64 " from account %s, total is %" PRIu64 "\n",
               transfer, from_acct->name, from_acct->balance);
        return head;
    }

    from_acct->balance -= transfer;
    printf("Withdrew %" PRIu64 " from account %s, total is now %" PRIu64 "\n", transfer,
           from_acct->name, from_acct->balance);
    log_event(from_acct, EVT_TRANSFER_OUT, &transfer, sizeof(transfer));

    to_acct->balance += transfer;
    printf("Deposited %" PRIu64 " into account %s, total is now %" PRIu64 "\n", transfer,
           to_acct->name, to_acct->balance);
    log_event(to_acct, EVT_TRANSFER_IN, &transfer, sizeof(transfer));

    if (to_acct->balance == 0) {
        free(to_acct->log);
        to_acct->active = !to_acct->active;
    }

    return head;
}

void win(void)
{
    int fd = open("/flag", O_RDONLY);
    sendfile(STDOUT_FILENO, fd, NULL, 1024);
    close(fd);
}

int main(void)
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    accounts_t *accounts = NULL;

    int choice;
    do {
        choice = 0;
        printf("What to do?\n"
               " [1] create\n"
               " [2] deposit\n"
               " [3] withdraw\n"
               " [4] transfer\n"
               " [9] exit\n"
               "> ");
        scanf("%i", &choice);
        getchar(); /* reading newline */

        switch (choice) {
        case 1:
            accounts = create(accounts);
            break;
        case 2:
            accounts = deposit(accounts);
            break;
        case 3:
            accounts = withdraw(accounts);
            break;
        case 4:
            accounts = transfer(accounts);
            break;
        default:
            printf("Invalid choice '%d'\n", choice);
            /* fallthrough */
        case 9:
            exit(EXIT_SUCCESS);
        }
    } while (true);
    __builtin_unreachable();
}
