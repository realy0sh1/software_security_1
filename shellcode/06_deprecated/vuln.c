#include <stdio.h>

int main(void)
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    char me[16] = "Tim";
    printf("Hello! My name is %p!\n", me);

    char name[16];
    printf("What is your name? ");
    gets(name);

    printf("Hello %s!\n", name);
}
