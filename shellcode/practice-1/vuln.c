#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

static void *const code_addr  = (void *) 0xaaaaaaa000;
static void *const stack_addr = (void *) 0x7ffffff000;
static const size_t code_size = 0x1000;
static const size_t stack_size = 0x1000;

unsigned long get_number(void) {
    char input[30];
    if (fgets(input, sizeof(input), stdin) == NULL)
        err(EXIT_FAILURE, "failed to read number");
    if (strlen(input) >= sizeof(input) - 1)
        errx(EXIT_FAILURE, "number input is too long");

    char *end = NULL;
    unsigned long value = strtoul(input, &end, 0);
    if (!end || (*end != '\0' && *end != '\r' && *end != '\n'))
        errx(EXIT_FAILURE, "%s is not (just) a number", input);

    return value;
}

int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    char *code = mmap(code_addr, code_size, PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0);
    if (code != code_addr)
        err(EXIT_FAILURE, "failed to map memory");

    char *stack = mmap(stack_addr, stack_size, PROT_READ | PROT_WRITE,
                       MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0);
    if (stack != stack_addr)
        err(EXIT_FAILURE, "failed to map memory");

    printf("How many numbers do you need? ");
    unsigned long count = get_number();
    if (count >= code_size / 10) {
        puts("That's too many numbers.");
        return EXIT_FAILURE;
    }

    for (size_t index = 0; index < count; ++index) {
        size_t offset = 10 * index;
        /* movabs rdi, number */
        code[offset + 0] = 0x48;
        code[offset + 1] = 0xb8;
        printf("Please enter number %zu: ", index + 1);
        unsigned long value = get_number();
        _Static_assert(sizeof(value) == 8, "Weird size for an unsigned long");
        memcpy(&code[offset + 2], &value, sizeof(value));
    }

    printf("Enter an offset to jump to: ");
    unsigned long offset = get_number();
    if (offset >= code_size) {
        puts("That's way too far.");
        return EXIT_FAILURE;
    }

    if (mprotect(code_addr, code_size, PROT_READ | PROT_EXEC))
        err(EXIT_FAILURE, "failed to change memory permissions");

    __asm__ volatile (
        "movq %[stack_end], %%rsp\n"
        "movq %[code], %%rax\n"
        "vzeroall\n"
        "xorl %%ebx, %%ebx\n"
        "xorl %%ecx, %%ecx\n"
        "xorl %%edx, %%edx\n"
        "xorl %%edi, %%edi\n"
        "xorl %%esi, %%esi\n"
        "xorl %%ebp, %%ebp\n"
        "xorl %%r8d, %%r8d\n"
        "xorl %%r9d, %%r9d\n"
        "xorl %%r10d, %%r10d\n"
        "xorl %%r11d, %%r11d\n"
        "xorl %%r12d, %%r12d\n"
        "xorl %%r13d, %%r13d\n"
        "xorl %%r14d, %%r14d\n"
        "xorl %%r15d, %%r15d\n"
        "call %%rax\n"
        "movl %%eax, %%edi\n"
        "movl %[exit_group], %%eax\n"
        "syscall\n"
        "hlt\n"
        :: [stack_end]"r"(stack + stack_size - 8),
           [code]"r"(code + offset),
           [exit_group]"i"(SYS_exit_group)
    );
    __builtin_unreachable();
}
