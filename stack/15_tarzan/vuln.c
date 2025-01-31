#include <unistd.h>
#include <stdio.h>

int main(void)
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);


    char buf2[20];
    char buf1[200];
    
    printf("[Jane] Here, Tarzan, this is called P R I N T F: %p\n", printf);
    printf("[Tarzan] ??? : %p\n", buf1);
    
    printf("Prepare your vine swing location:\n");
    read(STDIN_FILENO, buf1, 200);
    
    printf("Now swing to it:\n");
    read(STDIN_FILENO, buf2, 54);
    
    puts("Farewell, King of the Jungle...");
}
