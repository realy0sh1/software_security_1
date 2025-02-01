#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static char g_path[PATH_MAX] = {};
static pthread_mutex_t g_sync_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_sync_cond = PTHREAD_COND_INITIALIZER;


#if defined(DEBUG_PATH_OPERATIONS)
#define debug(fmt, ...) do { fprintf(stderr, "%s: " fmt, __func__, ##__VA_ARGS__); } while (0)
#else
#define debug(fmt, ...) do { } while (0)
#endif

static int apply_path(char *current, size_t current_size, char *subpath, int nesting);

static int go_to_parent(char *current) {
    // Go up a directory level: find the previous slash, and remove it and anything after it.
    char *sep = strrchr(current, '/');
    if (!sep) // Must always at least have /... or "/".
        errx(EXIT_FAILURE, "internal error: somehow we lost all slashes in the path...");
    else if (sep != current) // If the slash is not the first slash, just remove it.
        *sep = '\0';
    else // Otherwise, we're moving to the root.
        memcpy(current, "/\0", 2);
    return 0;
}

static int apply_path_component(char *current, size_t current_size, const char *component, int nesting) {
    debug("\x1b[32m%s\x1b[0m \x1b[31m%s\x1b[0m\n", current, component);
    if (strlen(component) == 0 || !strcmp(component, ".")) {
        // ./ and doubled slashes mean nothing, this is not Windows/URL parsing
        return 0;
    } else if (!strcmp(component, "..")) {
        return go_to_parent(current);
    } else {
        // Append the component
        if (strcmp(current, "/"))
            strncat(current, "/", current_size - 1);
        strncat(current, component, current_size - 1);

        // Check if this is a symbolic link
        struct stat statbuf = { 0 };
        if (lstat(current, &statbuf)) {
            printf("failed to lstat %s: %m\n", current);
            return -1;
        }
        if ((statbuf.st_mode & S_IFMT) == S_IFLNK) {
            // It is a symbolic link - where does it point?
            char link[PATH_MAX] = { 0 };
            if (readlink(current, link, sizeof(link) - 1) < 0) {
                printf("failed to read symbolic link %s: %m\n", current);
                return -1;
            }
            // This can either start with / (i.e., we replace the current path), or
            // not, then it is relative to wherever it is.
            if (link[0] == '/') {
                strncpy(current, link, current_size);
                return 0;
            } else {
                // We need to remove the actual symlink filename
                if (go_to_parent(current))
                    return -1;
                return apply_path(current, current_size, link, nesting + 1);
            }
        } else {
            // It isn't, we're done with this component.
            return 0;
        }
    }

}

static int apply_path(char *current, size_t current_size, char *subpath, int nesting) {
    debug("\x1b[32m%s\x1b[0m \x1b[31m%s\x1b[0m\n", current, subpath);
    if (subpath[0] == '/')
        errx(EXIT_FAILURE, "internal error: passed an absolute path to apply_path");

    if (nesting > 20) {
        // Basically -ELOOP
        printf("too many nested symbolic links\n");
        return -1;
    }

    char *saved = NULL;
    char *component = strtok_r(subpath, "/", &saved);
    do {
        if (apply_path_component(current, current_size, component, nesting))
            return -1;
    } while ((component = strtok_r(NULL, "/", &saved)));
    return 0;
}

static void send_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("failed to open %s: %m\n", g_path);
        return;
    }

    struct stat statbuf = { 0 };
    if (fstat(fd, &statbuf)) {
        printf("failed to stat %s: %m\n", g_path);
        goto close;
    }

    if (statbuf.st_size > 0x4000) {
        printf("%s is too large\n", g_path);
        goto close;
    }

    size_t remaining = statbuf.st_size;
    while (remaining) {
        ssize_t sent = sendfile(STDOUT_FILENO, fd, NULL, remaining);
        if (sent <= 0) {
            printf("failed to send %s: %m\n", g_path);
            goto close;
        }
        remaining -= sent;
    }

close:
    close(fd);
}

void worker(void) {
    for (;;) {
        // Wait for the parent to notify us
        if (pthread_mutex_lock(&g_sync_mutex))
            errx(EXIT_FAILURE, "failed to lock mutex");
        if (pthread_cond_wait(&g_sync_cond, &g_sync_mutex))
            errx(EXIT_FAILURE, "failed to wait for notification");
        if (pthread_mutex_unlock(&g_sync_mutex))
            errx(EXIT_FAILURE, "failed to unlock mutex");

        // Check that the path is OK to read
        char current[PATH_MAX] = { 0 };
        char *writable = strdup(g_path);
        if (!writable)
            errx(EXIT_FAILURE, "failed to allocate memory");

        // If this is an absolute path, start at / (and trim the leading slashes), else start at the current directory
        char *cursor = writable;
        if (*cursor == '/') {
            // Absolute path
            *current = '/';
            while (*cursor == '/')
                ++cursor;
        } else {
            // Relative path, grab current directory
            if (!getcwd(current, sizeof(current) - 1))
                err(EXIT_FAILURE, "getcwd failed (path too long?)");
            // Make sure there's no slash at the end.
            while (strlen(current) && current[strlen(current) - 1] == '/')
                current[strlen(current) - 1] = '\0';
        }

        // Get the actual resolved path of this file
        if (apply_path(current, sizeof(current), cursor, 0))
            continue;
        debug("final path is \x1b[32m%s\x1b[0m\n", current);
        free(writable);

        // Check that it's in our home directory
        char buffer[1024] = { 0 };
        struct passwd pwd, *result;
        if (getpwuid_r(getuid(), &pwd, buffer, sizeof(buffer), &result))
            err(EXIT_FAILURE, "getpwuid_r failed to get passwd entry");
        if (!result)
            err(EXIT_FAILURE, "no passwd entry for the current user");
        
        if (strncmp(pwd.pw_dir, current, strlen(pwd.pw_dir))) {
            printf("%s is outside of your home directory\n", g_path);
            continue;
        }
            
        // If so, print the file
        send_file(g_path);
    }
}

void *worker_wrapper(void *arg) {
    // This is just here to comply with the pthreads API, we don't actually have arguments/results
    (void) arg;
    worker();
    return NULL;
}

int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    pthread_t worker_thread;
    if (pthread_create(&worker_thread, NULL, worker_wrapper, NULL))
        errx(EXIT_FAILURE, "failed to create worker thread");

    for (;;) {
        printf("Enter file to read: ");
        if (!fgets(g_path, sizeof(g_path), stdin))
            err(EXIT_FAILURE, "failed to read input");

        size_t length = strlen(g_path);
        if (g_path[length - 1] == '\n')
            g_path[length - 1] = '\0';
        if (!strlen(g_path))
            continue;

        if (pthread_mutex_lock(&g_sync_mutex))
            errx(EXIT_FAILURE, "failed to lock mutex");
        debug("signaling \x1b[32m%s\x1b[0m", g_path);
        if (pthread_cond_signal(&g_sync_cond))
            errx(EXIT_FAILURE, "failed to signal worker");
        if (pthread_mutex_unlock(&g_sync_mutex))
            errx(EXIT_FAILURE, "failed to unlock mutex");
    }
}
