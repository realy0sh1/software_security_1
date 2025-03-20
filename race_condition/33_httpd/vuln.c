#define _GNU_SOURCE
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define log(message, ...) do { dprintf(STDERR_FILENO, message "\n", ##__VA_ARGS__); } while (0)
#define die(message, ...) do { dprintf(STDERR_FILENO, message "\n", ##__VA_ARGS__); _Exit(1); } while (0)

#define NO_CONTENT               "HTTP/1.0 204 No Content\r\n\r\n"
#define BAD_HOST                 "HTTP/1.0 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 24\r\n\r\nIncorrect Host header.\r\n"
#define BAD_REQUEST              "HTTP/1.0 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 58\r\n\r\nYou sent a request that the server could not understand.\r\n"
#define FORBIDDEN                "HTTP/1.0 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 57\r\n\r\nYou are not permitted to access the requested resource.\r\n"
#define NOT_FOUND                "HTTP/1.0 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 40\r\n\r\nThe requested resource does not exist.\r\n"
#define METHOD_NOT_ALLOWED       "HTTP/1.0 405 Method Not Allowed\r\nContent-Type: text/plain\r\nContent-Length: 57\r\n\r\nThe requested method is not supported by this resource.\r\n"
#define LENGTH_REQUIRED          "HTTP/1.0 411 Length Required\r\nContent-Type: text/plain\r\nContent-Length: 57\r\n\r\nThe request does not specify the length of its content.\r\n"
#define PAYLOAD_TOO_LARGE        "HTTP/1.0 413 Payload Too Large\r\nContent-Type: text/plain\r\nContent-Length: 53\r\n\r\nThe request is too large for this server to handle.\r\n"
#define INTERNAL_SERVER_ERROR    "HTTP/1.0 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: 32\r\n\r\nFailed to handle this request.\r\n"
#define ENCODING_NOT_IMPLEMENTED "HTTP/1.0 501 Not Implemented\r\nContent-Type: text/plain\r\nContent-Length: 60\r\n\r\nThe specified transfer or content encoding is unsupported.\r\n"
#define TEMPORARILY_UNAVAILABLE  "HTTP/1.0 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 67\r\n\r\nThis resource is temporarily unavailable, please try again later.\r\n"
#define SERVER_OVERLOADED        "HTTP/1.0 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 63\r\n\r\nThis service is currently overloaded, please try again later.\r\n"

#define SERVER_HOST "httpd.tasks.softsec.rub.de:1024"
#define SERVER_PORT 1024

#define MAX_BODY_SIZE (8ul * 1024 * 1024)
#define MAX_LINE_SIZE 4096

struct connection {
    int fd;
    FILE *file;
    struct timespec start;
    char *log;
};

static ssize_t write_all(int fd, const char *message, size_t length)
{
    while (length > 0) {
        ssize_t bytes = write(fd, message, length);
        if (bytes < 0)
            return bytes;
        message += bytes;
        length -= bytes;
    }
    return 0;
}

static ssize_t sendfile_all(int fd_out, int fd_in, off_t *off_in, size_t length)
{
    while (length > 0) {
        ssize_t bytes = sendfile(fd_out, fd_in, off_in, length);
        if (bytes < 0)
            return bytes;
        length -= bytes;
    }
    return 0;
}

void connection_log_vappend(struct connection *conn, const char *fmt, va_list vlist)
{
    va_list copied;
    va_copy(copied, vlist);

    size_t existing = conn->log ? strlen(conn->log) + 1 : 0;
    size_t size = vsnprintf(NULL, 0, fmt, copied);
    va_end(copied);

    char *buf = realloc(conn->log, existing + size + 1);
    if (buf) {
        if (existing)
            buf[existing - 1] = ' ';
        vsnprintf(&buf[existing], size + 1, fmt, vlist);
        conn->log = buf;
    }
}

void connection_log_append(struct connection *conn, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    connection_log_vappend(conn, fmt, args);
    va_end(args);
}

void connection_log(struct connection *conn, const char *fmt, ...)
{
    // Log the client IP at the start of each line.
    if (!conn->log && conn->fd) {
        struct sockaddr_in client_addr;
        socklen_t ipv4_addr_len = sizeof(client_addr);
        if (getpeername(conn->fd, (struct sockaddr *) &client_addr, &ipv4_addr_len) == 0) {
            char ipv4_addr_buffer[INET_ADDRSTRLEN + 1] = { 0 };
            const char *ipv4_addr = inet_ntop(AF_INET, &client_addr.sin_addr, ipv4_addr_buffer, sizeof(ipv4_addr_buffer));
            if (!!ipv4_addr)
                connection_log_append(conn, "%s:%d", ipv4_addr, ntohs(client_addr.sin_port));

            char host_buffer[256];
            if (getnameinfo((struct sockaddr *) &client_addr, sizeof(client_addr), host_buffer, sizeof(host_buffer), NULL, 0, NI_NAMEREQD) == 0)
                connection_log_append(conn, "(%s)", host_buffer);
        }
    }
    // Then, add the content
    va_list args;
    va_start(args, fmt);
    connection_log_vappend(conn, fmt, args);
    va_end(args);
}

void connection_log_status(struct connection *conn, int status)
{
    connection_log(conn, "=> %03d", status);
}

void connection_close(struct connection *conn)
{
    assert(conn != NULL);
    if (conn->file)
        fclose(conn->file); // This should also close the file descriptor
    else if (conn->fd >= 0)
        close(conn->fd);
    conn->file = NULL;
    conn->fd = -1;

    // Print the log entry
    if (conn->log) {
        struct timespec now;
        struct tm local;
        char ts[64] = { 0 };

        clock_gettime(CLOCK_MONOTONIC, &now);
        double seconds = (now.tv_sec + (double) now.tv_nsec / 1000000000) - \
                         (conn->start.tv_sec + (double) conn->start.tv_nsec / 1000000000);

        clock_gettime(CLOCK_REALTIME, &now);
        localtime_r(&now.tv_sec, &local);
        strftime(ts, sizeof(ts), "%H:%M:%S", &local);
        dprintf(STDERR_FILENO, "%s (%6.4fs, %s.%03ld)\n", conn->log, seconds, ts, now.tv_nsec / 1000000);
        free(conn->log);
        conn->log = NULL;
    }
}

void connection_close_with(struct connection *conn, const char *message)
{
    assert(conn != NULL);
    if (conn->file)
        fflush(conn->file);
    if (conn->fd >= 0)
        write_all(conn->fd, message, strlen(message));
    connection_log_status(conn, atoi(&message[9]));
    connection_close(conn);
}

char *http_read_line(struct connection *conn)
{
    assert(conn != NULL);
    assert(conn->file != NULL);

    char *into = NULL;
    size_t space = 0;
    ssize_t bytes = getline(&into, &space, conn->file);
    if (bytes < 0 || !*into) {
        if (feof(conn->file)) {
            connection_log(conn, "Connection closed before request could be read");
            connection_close(conn);
        } else {
            connection_log(conn, "Failed to read request from connection: %m");
            connection_close_with(conn, INTERNAL_SERVER_ERROR);
        }
        return NULL;
    } else if (bytes < 2 || bytes > MAX_LINE_SIZE || into[bytes - 1] != '\n' || into[bytes - 2] != '\r') {
        // Line is either too short, too long, or not terminated with \r\n as required by HTTP
        free(into);
        connection_close_with(conn, BAD_REQUEST);
        return NULL;
    }
    into[bytes - 2] = '\0';
    return into;
}

// send file from path
void handle_get(struct connection *conn, char *path)
{
    int filefd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat sb;

    if (filefd < 0) { // Failed to open file for reading
        switch (errno) {
            case EINVAL: case ENODEV: case ENOENT: case ENOTDIR:
                connection_close_with(conn, NOT_FOUND);
                break;
            case EACCES: case EISDIR: case ELOOP: case ENAMETOOLONG: case ENXIO: case EPERM: case EROFS:
                connection_close_with(conn, FORBIDDEN);
                break;
            case EBUSY: case EMFILE: case ENFILE: case ENOMEM: case ETXTBSY: case EWOULDBLOCK:
                connection_close_with(conn, TEMPORARILY_UNAVAILABLE);
                break;
            default:
                log("Failed to open '%s' for reading: %m", path);
                connection_close_with(conn, INTERNAL_SERVER_ERROR);
                break;
        }
    } else if (fstat(filefd, &sb)) { // Failed to stat file - this shouldn't happen if we managed to open it
        connection_close_with(conn, INTERNAL_SERVER_ERROR);
    } else if ((sb.st_mode & S_IFMT) != S_IFREG) { // Not a regular file
        connection_close_with(conn, FORBIDDEN);
    } else { // Send the file
        connection_log_status(conn, 200);
        fprintf(conn->file, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %ld\r\n\r\n", sb.st_size);
        fflush(conn->file);
        sendfile_all(conn->fd, filefd, NULL, sb.st_size);
    }

    if (filefd >= 0)
        close(filefd);
}

// rename file
void handle_post(struct connection *conn, char *path, size_t length)
{
    // This is a bit of an abuse since this is not strictly REST (more like WebDAV),
    // but oh well.
    const char *error = INTERNAL_SERVER_ERROR;
    char *new_name = calloc(length + 1, 1);
    char *new_path = NULL;
    if (!new_name)
        goto on_error; // Failed to allocate memory

    error = BAD_REQUEST;
    if (fread(new_name, 1, length, conn->file) < length)
        goto on_error; // Bad request: Request truncated

    error = INTERNAL_SERVER_ERROR;
    char *filename_start = strrchr(path, '/');
    if (filename_start) {
        // replace last / in path with zero to tempory get path
        *filename_start = '\0';
        if (asprintf(&new_path, "%s/%s", path, new_name) < 0)
            goto on_error; // Failed to construct path
        *filename_start = '/';
    } else {
        new_path = strdup(new_name);
        if (!new_path)
            goto on_error; // Failed to allocate memory
    }

    error = FORBIDDEN;
    if (strchr(new_name, '/'))
        goto on_error; // I want a file name, not a path.

    struct stat sb;
    if (stat(path, &sb) || (sb.st_mode & S_IFMT) != S_IFREG)
        goto on_error; // Doesn't exist or isn't a regular file

    if (rename(path, new_path)) {
        switch (errno) {
            case ENOENT: case ENOTDIR:
                error = NOT_FOUND;
                break;
            case EACCES: case EDQUOT: case EEXIST: case EINVAL: case EISDIR: case ELOOP: case EMLINK: case ENAMETOOLONG: case ENOTEMPTY: case EPERM: case EROFS: case EXDEV:
                error = FORBIDDEN;
                break;
            case EBUSY: case ENOMEM:
                error = TEMPORARILY_UNAVAILABLE;
                break;
            default:
                log("Failed to rename '%s' to '%s': %m", path, new_path);
                error = INTERNAL_SERVER_ERROR;
                break;
        }
    } else {
        // Pretend this is an error - it's the same handling anyways
        error = NO_CONTENT;
    }

on_error:
    free(new_name);
    free(new_path);
    connection_close_with(conn, error);
    return;
}

// send file to server and store at path of our choice
void handle_put(struct connection *conn, char *path, size_t length)
{
    // Recursively make directories (all given in path)
    for (char *sep = strchr(path, '/'); sep; sep = strchr(sep, '/')) {
        // replace current / with end of string
        *sep = '\0';
        if (mkdir(path, 0755) < 0 && errno != EEXIST) {
            connection_close_with(conn, FORBIDDEN);
            return;
        }
        *sep = '/';
    }

    struct stat sb;
    if (!stat(path, &sb) && (sb.st_mode & S_IFMT) != S_IFREG) { // Exists and isn't a regular file
        connection_close_with(conn, FORBIDDEN);
        return;
    }

    int filefd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (filefd < 0) { // Failed to open file for reading
        switch (errno) {
            case EINVAL: case ENODEV: case ENOENT: case ENOTDIR:
                connection_close_with(conn, NOT_FOUND);
                break;
            case EACCES: case EDQUOT: case EISDIR: case ELOOP: case ENAMETOOLONG: case ENOSPC: case ENXIO: case EPERM: case EROFS:
                connection_close_with(conn, FORBIDDEN);
                break;
            case EBUSY: case EMFILE: case ENFILE: case ENOMEM: case ETXTBSY: case EWOULDBLOCK:
                connection_close_with(conn, TEMPORARILY_UNAVAILABLE);
                break;
            default:
                log("Failed to open '%s' for writing: %m", path);
                connection_close_with(conn, INTERNAL_SERVER_ERROR);
                break;
        }
    } else {
        // Unfortunately we can't use the connection fd here since things might be buffered in the file.
        char buffer[2048];
        while (length) {
            size_t to_transfer = length < sizeof(buffer) ? length : sizeof(buffer);
            if (fread(buffer, 1, to_transfer, conn->file) < to_transfer) {
                connection_close_with(conn, BAD_REQUEST);
                break;
            }
            if (write_all(filefd, buffer, to_transfer) < 0) {
                connection_close_with(conn, INTERNAL_SERVER_ERROR);
                break;
            }
            length -= to_transfer;
        }
        if (length == 0) // Transferred everything
            connection_close_with(conn, NO_CONTENT);
    }

    if (filefd >= 0)
        close(filefd);
}

void handle_delete(struct connection *conn, char *path)
{
    if (unlink(path)) {
        switch (errno) {
            case ENOENT: case ENOTDIR:
                connection_close_with(conn, NOT_FOUND);
                break;
            case EACCES: case EISDIR: case ELOOP: case ENAMETOOLONG: case EPERM: case EROFS:
                connection_close_with(conn, FORBIDDEN);
                break;
            default:
                log("Failed to unlink '%s': %m", path);
                connection_close_with(conn, INTERNAL_SERVER_ERROR);
                break;
        }
    } else {
        connection_close_with(conn, NO_CONTENT);
    }
}

// NOTE: this function is called for each connection in a new thread
// NOTE: strtok is not thread safe
void handle_connection(struct connection *conn)
{
    const char *error = BAD_REQUEST;

    char *start_line = http_read_line(conn);
    if (!start_line)
        return; // Already closed the connection on error.

    // Split the start line into its components
    char *http_method = strtok(start_line, " ");

    if (!http_method)
        goto on_error; // Invalid starting line
    connection_log(conn, "%s", http_method);

    char *request_path = strtok(NULL, " ");

    if (!request_path)
        goto on_error; // Invalid starting line
    connection_log(conn, "'%s'", request_path);

    char *http_version = strtok(NULL, " ");

    if (!http_version)
        goto on_error; // Invalid starting line
    connection_log(conn, "%s", http_version);

    if (!strlen(http_method) || !strlen(request_path) || !strlen(http_version))
        goto on_error; // Invalid starting line
    if (request_path[0] != '/')
        goto on_error; // Invalid path
    if (strcmp(http_version, "HTTP/1.0") && strcmp(http_version, "HTTP/1.1"))
        goto on_error; // Unsupported HTTP version

    // Check paths
    error = FORBIDDEN;
    char *relative_path = &request_path[1];
    char *filename = strrchr(request_path, '/') ?: relative_path;
    if (relative_path[0] == '/')
        goto on_error;
    if (strstr(relative_path, "../"))
        goto on_error;
    if (!strcmp(filename, "flag"))
        goto on_error;

    // Collect headers that we're interested in, and skip the rest.
    error = BAD_REQUEST;
    int host_headers = 0; // In HTTP/1.1, there must be exactly one Host header.
    size_t content_length = 0; // If we have a POST or PUT request, we need a content length
    for (size_t header_length = SIZE_MAX; header_length;) {
        char *header = http_read_line(conn);
        if (!header)
            return; // http_read_line handles errors itself

        // Stop after this header if it is empty (then, the body starts)
        header_length = strlen(header);

        // In HTTP/1.1, check for Host headers. We don't care about them in HTTP/1.0.
        // However, if one is present, make sure it says the request is supposed to
        // go here.
        if (!strncmp(header, "Host: ", 6)) {
            ++host_headers;
            if (strcmp(&header[6], SERVER_HOST)) {
                error = BAD_HOST;
                goto on_error; // Bad request: Request directed at the wrong host.
            }
        }

        // If there's a Content-Encoding or Transfer-Encoding header, reject it
        // (we don't understand chunked messages, and there's no value for Content-Length only)
        if (!strncmp(header, "Content-Encoding: ", 18) || !strncmp(header, "Transfer-Encoding: ", 19)) {
            error = ENCODING_NOT_IMPLEMENTED;
            goto on_error;
        }

        // If there's a Content-Length header, parse the length
        if (!strncmp(header, "Content-Length: ", 16)) {
            if (content_length)
                goto on_error; // Bad request: Multiple Content-Length headers
            char *end = NULL;
            errno = 0;
            content_length = strtoul(&header[16], &end, 10);
            if (errno || !end || *end != '\0')
                goto on_error; // Bad request: Invalid value for Content-Length
            if (content_length >= MAX_BODY_SIZE) {
                error = PAYLOAD_TOO_LARGE;
                goto on_error; // Payload too large
            }
            if (content_length == 0)
                goto on_error; // Bad request: Not willing to handle empty requests.
        }
    }
    if (!strcmp(http_version, "HTTP/1.1") && host_headers != 1)
        goto on_error; // Bad request: No or multiple Host headers

    if (!content_length && (!strcmp(http_method, "POST") || !strcmp(http_method, "PUT"))) {
        error = LENGTH_REQUIRED;
        goto on_error; // Length required: No Content-Length header.
    }

    // Check method and dispatch
    error = METHOD_NOT_ALLOWED;
    if (strcmp(http_method, "GET") == 0)
        handle_get(conn, relative_path);
    else if (strcmp(http_method, "POST") == 0)
        handle_post(conn, relative_path, content_length);
    else if (strcmp(http_method, "PUT") == 0)
        handle_put(conn, relative_path, content_length);
    else if (strcmp(http_method, "DELETE") == 0)
        handle_delete(conn, relative_path);
    else
        goto on_error;

    free(start_line);
    connection_close(conn);
    return;

on_error:
    free(start_line);
    connection_close_with(conn, error);
}

void *handle_connection_wrapper(void *arg)
{
    int fd = (int) (uintptr_t) arg;
    struct connection conn = {
        .fd = fd,
        .file = fdopen(fd, "r+"),
        .start = { 0 },
        .log = NULL,
    };
    clock_gettime(CLOCK_MONOTONIC, &conn.start);

    if (conn.file) {
        handle_connection(&conn);
    } else {
        log("Failed to fdopen connection: %m");
        connection_close_with(&conn, INTERNAL_SERVER_ERROR);
    }
    return NULL;
}

int main(void)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0)
        die("Failed to open socket: %m");

    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)))
        die("Failed to set SO_REUSEADDR: %m");

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    switch (inet_pton(AF_INET, "0.0.0.0", &addr.sin_addr)) {
        case 1: break;
        case 0: die("Failed to parse IP address: Invalid address");
        default: die("Failed to parse IP address: %m");
    }

    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)))
        die("Failed to bind socket: %m");

    if (listen(sockfd, 128))
        die("Failed to start listening on socket: %m");

    fputs("Server is ready.\n", stderr);
    for (;;) {
        int conn = accept(sockfd, NULL, 0);
        if (conn < 0)
            die("Failed to accept incoming connection: %m");

        pthread_t thread;
        if ((errno = pthread_create(&thread, NULL, handle_connection_wrapper, (void *) (uintptr_t) conn))) {
            log("Failed to spawn thread for incoming connection: %m");
            write_all(conn, SERVER_OVERLOADED, strlen(SERVER_OVERLOADED));
            close(conn);
        } else {
            pthread_detach(thread);
        }
    }

    return 0;
}
