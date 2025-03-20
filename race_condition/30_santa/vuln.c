#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct action {
    const char *text;
    void (*perform)(int fd, bool nice);
    bool nice;
};

void eat_vegetables(int fd, bool nice) { dprintf(fd, "Yuck.\n"); }
void steal_candy(int fd, bool nice) { dprintf(fd, "Yummy!\n"); }
void bully_sally(int fd, bool nice) { dprintf(fd, "Poor Sally.\n"); }

void get_presents(int fd, bool nice)
{
    char flag_buffer[128] = { 0 };
    if (nice) {
        FILE *flag_file = fopen("/flag", "r");
        if (!flag_file || !fgets(flag_buffer, sizeof(flag_buffer), flag_file))
            strncpy(flag_buffer, "Failed to read flag file, please contact the admins...\n", sizeof(flag_buffer));
        if (flag_file)
            fclose(flag_file);
    } else {
        strncpy(flag_buffer, "Only coal for you.\n", sizeof(flag_buffer));
    }
    dprintf(fd, "%s", flag_buffer);
}

struct action actions[] = {
    { "Eat your vegetables", eat_vegetables, true },
    { "Steal some candy", steal_candy, false },
    { "Bully Sally", bully_sally, false },
    { "Get presents", get_presents, false },
    { NULL, NULL, false },
};

struct action **history = NULL;
size_t history_size = 0;
size_t history_cap = 0;

void add_to_history(struct action *action)
{
    if (history_size >= history_cap) {
        history_cap = history_cap ? (history_cap * 2) : 32;
        // realloc frees history and other thread meight still use it
        history = realloc(history, sizeof(struct action *) * history_cap);
        if (!history)
            err(EXIT_FAILURE, "failed to allocate memory");
    }
    history[history_size++] = action;
}

bool check_naughty_list(void)
{
    // when a new instance starts, history size is set to zero
    for (size_t i = 0; i < history_size; ++i)
        if (!history[i]->nice)
            return false;
    return true;
}

void handle_connection(int fd)
{
    history_size = 0; // Start with a clean slate
    for (;;) {
next:
        dprintf(fd, "What do you want to do?\n> ");

        char command[64] = { 0 };
        for (size_t i = 0;; ++i) {
            char c; // Try to read the command byte-by-byte.
            if (read(fd, &c, 1) <= 0) {
                return;
            } else if (c == '\r' || c == '\n') {
                break; // Stop on newline
            } else if (i >= sizeof(command) - 1) {
                command[sizeof(command) - 1] = '\0';
                continue; // Don't overflow, but keep reading until newline.
            } else {
                command[i] = c;
            }
        }
            
        for (struct action *a = actions; a->text; ++a) {
            if (!strcmp(command, a->text)) {
                // first entry triggers realloc => do 2 at once => race condition what histroy is
                add_to_history(a); // Remember what you did.
                // we send as 33-th entry one nice one naughty
                // - add naughty (realloc)
                // - add nice (realloc)
                // - now naughty entry is checked, but global list is now nice only
                bool nice = check_naughty_list(); // Are you on the naughty list, or not?
                a->perform(fd, nice);
                goto next;
            }
        }
        if (!strcmp(command, "Leave"))
            return;
        dprintf(fd, "You can't do that.\n");
    }

}

void *handle_connection_wrapper(void *arg)
{
    int fd = (int) (uintptr_t) arg;
    handle_connection(fd);
    close(fd);
    return NULL;
}

#define SERVER_PORT 1024

int main(void)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0)
        err(EXIT_FAILURE, "Failed to open socket");

    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)))
        err(EXIT_FAILURE, "Failed to set SO_REUSEADDR");

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    switch (inet_pton(AF_INET, "0.0.0.0", &addr.sin_addr)) {
        case 1: break;
        case 0: err(EXIT_FAILURE, "Failed to parse IP address: Invalid address");
        default: err(EXIT_FAILURE, "Failed to parse IP address");
    }

    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)))
        err(EXIT_FAILURE, "Failed to bind socket");

    if (listen(sockfd, 128))
        err(EXIT_FAILURE, "Failed to start listening on socket");

    signal(SIGPIPE, SIG_IGN);

    fputs("Server is ready.\n", stderr);
    for (;;) {
        int conn = accept(sockfd, NULL, 0);
        if (conn < 0)
            err(EXIT_FAILURE, "Failed to accept incoming connection");

        pthread_t thread;
        void *thread_arg = (void *) (uintptr_t) conn;

        // i can do multiple connections :)
        // each connection calls handle_connection_wrapper -> handle_connection

        if ((errno = pthread_create(&thread, NULL, handle_connection_wrapper, thread_arg))) {
            warn("Failed to spawn thread for incoming connection");
            ssize_t written = write(conn, "Server is overloaded\n", 21);
            (void) written;
            close(conn);
        } else {
            pthread_detach(thread);
        }
    }

    return 0;
}
