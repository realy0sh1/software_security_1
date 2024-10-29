#include <unistd.h>

int main(void)
{
    volatile unsigned this_may_be_useful = 0xc35ec35f;

    char buf[20];
    write(STDOUT_FILENO, "Hello, what's your name?\n", 25);
    read(STDIN_FILENO, buf, 200);
}
