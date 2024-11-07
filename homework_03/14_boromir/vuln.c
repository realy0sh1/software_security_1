#include <unistd.h>
#include <stdio.h>

int main(void)
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    printf("[Samwise Gamgee] This is the localtion of the printf mountains, Mr. Frodo: %p\n", printf);

    char buffer[20];
    read(0, buffer, 48);
    
    return 0;
}
