#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *fmt = NULL;
ssize_t fmt_len = 0;

void set(void)
{
	ssize_t buf_len = 0;

	printf("What is the length of the new format?\n> ");

	if (1 != scanf("%ld", &buf_len)) {
		errx(EXIT_FAILURE, "unable to read length");
	}

	if (buf_len < 0) {
		errx(EXIT_FAILURE, "length must be non-negative");
	}

	char *buf = calloc(buf_len, sizeof(char));
	if (NULL == buf) {
		errx(EXIT_FAILURE, "calloc failed");
	}

	printf("What is the new format?\n> ");
	ssize_t buf_read = 0;
	do {
		ssize_t rv = read(STDIN_FILENO, buf + buf_read, buf_len - buf_read);
		if (rv < 0) {
			errx(EXIT_FAILURE, "read failed");
		}
		buf_read += rv;
	} while (buf_read < buf_len);

	/* We do not allow any %<specifier> in the new format string (with or without prefixes).
	 * Our check is overly conservative and we are bad at regexs.
	 * Better manually check, then it is definitely safe.
	 */
	bool percent = false;
	for (ssize_t i = 0; i < buf_len; ++i) {
		if (buf[i] == '%') {
			percent = true;
		} else if (percent &&
			   (buf[i] == 'd' || buf[i] == 'i' || buf[i] == 'o' || buf[i] == 'u' ||
			    buf[i] == 'x' || buf[i] == 'X' || buf[i] == 'D' || buf[i] == 'O' ||
			    buf[i] == 'U' || buf[i] == 'e' || buf[i] == 'E' || buf[i] == 'f' ||
			    buf[i] == 'F' || buf[i] == 'g' || buf[i] == 'G' || buf[i] == 'a' ||
			    buf[i] == 'A' || buf[i] == 'C' || buf[i] == 'c' || buf[i] == 'S' ||
			    buf[i] == 's' || buf[i] == 'p' || buf[i] == 'n')) {
			errx(EXIT_FAILURE, "format string contains %%(.*)%c", buf[i]);
		}
	}

	if (buf_len > fmt_len) {
		fmt = realloc(fmt, buf_len + 1);
		if (NULL == fmt) {
			errx(EXIT_FAILURE, "realloc failed");
		}
		fmt_len = buf_len + 1;
		fmt[buf_len] = '\0';
	}

	memcpy(fmt, buf, buf_len);
}

void print(void)
{
	if (NULL == fmt) {
		errx(EXIT_FAILURE, "fmt is not initalized, call set first");
	}

	printf("Output:\n");
	/* fmt is sanitized via set(), there are no conversions in here */
	printf(fmt);
	printf("\n");
}

int main(void)
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	uint8_t choice = 0;
	do {
		printf("Option? 1:set 2:print\n> ");
		if (1 != scanf("%hhu", &choice)) {
			errx(EXIT_FAILURE, "unable to read choice");
		}
		switch (choice) {
		case 1:
			set();
			break;
		case 2:
			print();
			break;
		default:
			choice = 0;
		}
	} while (choice != 0);

	exit(EXIT_SUCCESS);
}
