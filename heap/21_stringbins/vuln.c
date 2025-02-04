#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

size_t strings_n = 0;
size_t *strings_l = NULL;
unsigned char **strings_p = NULL;

void alloc(void)
{
	size_t len = 0;
	printf("[*] How long is the string?\n");
	scanf("%lu", &len);
	getchar(); /* reading newline */

	unsigned char *str = malloc(len);
	printf("[*] Reading %lu characters to %p.\n", len, str);
	if (str == NULL) {
		exit(EXIT_FAILURE);
	}
	bzero(str, len);

	for (size_t i = 0; i < len; ++i) {
		int t = getchar();
		if (t == EOF) {
			printf("[E] Cannot read byte from stdin, has it been closed?\n");
			exit(EXIT_FAILURE);
		}
		str[i] = t;
	}
	printf("    OK, I read '%s' to %p.\n", str, str);
	getchar(); /* reading newline */

	strings_n += 1;
	strings_p = realloc(strings_p, sizeof(unsigned char *) * strings_n);
	strings_l = realloc(strings_l, sizeof(size_t) * strings_n);
	if (strings_p == NULL) {
		exit(EXIT_FAILURE);
	}
	strings_p[strings_n - 1] = str;
	strings_l[strings_n - 1] = len;
}

void print(void)
{
	size_t idx = -1;
	printf("[*] What string index should I print?\n");
	scanf("%lu", &idx);
	getchar(); /* reading newline */

	if (idx == -1 || idx > strings_n) {
		exit(EXIT_FAILURE);
	}

	printf("s[%lu] = %s\n", idx, strings_p[idx]);
}

void list(void)
{
	printf("[*] The following strings have been used:\n");
	for (size_t idx = 0; idx < strings_n; ++idx) {
		printf("    char[%lu] s[%lu] @ %p\n", strings_l[idx], idx, strings_p[idx]);
	}
}

void dealloc(void)
{
	size_t idx = -1;
	printf("[*] What string index should I free?\n");
	scanf("%lu", &idx);
	getchar(); /* reading newline */

	if (idx == -1 || idx > strings_n) {
		exit(EXIT_FAILURE);
	}

	free(strings_p[idx]);
	printf("[*] OK, I free'd index %lu.\n", idx);
}

void change(void)
{
	size_t len = 0;
	printf("[*] How many characters should I update?\n");
	scanf("%lu", &len);
	getchar(); /* reading newline */

	unsigned char *temp_str = alloca(len);
	printf("[*] Reading %lu bytes to temporary %p.\n", len, temp_str);

	for (size_t i = 0; i < len; ++i) {
		int t = getchar();
		if (t == EOF) {
			printf("[E] Cannot read byte from stdin, has it been closed?\n");
			exit(EXIT_FAILURE);
		}
		temp_str[i] = t;
	}
	getchar(); /* reading newline */

	size_t idx = -1;
	printf("[*] What string index should I update?\n");
	scanf("%lu", &idx);
	getchar(); /* reading newline */

	if (idx >= strings_n) {
		printf("[E] The index %lu is not allocated... nice try.\n", idx);
		exit(EXIT_FAILURE);
	}

	bzero(strings_p[idx], strings_l[idx]);
	memcpy(strings_p[idx], temp_str, strings_l[idx] > len ? len : strings_l[idx]);
}

int main(void)
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	int choice;
	do {
		choice = 0;
		printf("[*] What should I do?\n"
		       "    1: allocate"
		       " -- 2: deallocate"
		       " -- 3: list"
		       " -- 4: print"
		       " -- 5: change"
		       " -- 6: exit\n");
		scanf("%i", &choice);
		getchar(); /* reading newline */
		switch (choice) {
		case 1:
			alloc();
			break;
		case 2:
			dealloc();
			break;
		case 3:
			list();
			break;
		case 4:
			print();
			break;
		case 5:
			change();
			break;
		case 6:
			return EXIT_SUCCESS;
		default:
			printf("[E] Invalid choice '%d', exiting\n", choice);
			return EXIT_FAILURE;
		}
	} while (choice >= 1 && choice <= 5);
	return EXIT_SUCCESS;
}
