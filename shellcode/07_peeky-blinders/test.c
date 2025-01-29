#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// gcc test.c -o test
// objdump -M intel -d ./test


int main(){
    char flag_byte;

    int fd_flag = open("/flag", O_RDONLY);
    read(fd_flag, &flag_byte, 1);

    if (flag_byte ==0x42) {
        while (1) {}
    } else {
        return 0;
    }
}
/*
0000000000001189 <main>:
    1189:       f3 0f 1e fa             endbr64 
    118d:       55                      push   rbp
    118e:       48 89 e5                mov    rbp,rsp
    1191:       48 83 ec 10             sub    rsp,0x10
    1195:       64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
    119c:       00 00 
    119e:       48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax
    11a2:       31 c0                   xor    eax,eax
    11a4:       be 00 00 00 00          mov    esi,0x0
    11a9:       48 8d 05 54 0e 00 00    lea    rax,[rip+0xe54]        # 2004 <_IO_stdin_used+0x4>
    11b0:       48 89 c7                mov    rdi,rax
    11b3:       b8 00 00 00 00          mov    eax,0x0
    11b8:       e8 d3 fe ff ff          call   1090 <open@plt>
    11bd:       89 45 f4                mov    DWORD PTR [rbp-0xc],eax
    11c0:       48 8d 4d f3             lea    rcx,[rbp-0xd]
    11c4:       8b 45 f4                mov    eax,DWORD PTR [rbp-0xc]
    11c7:       ba 01 00 00 00          mov    edx,0x1
    11cc:       48 89 ce                mov    rsi,rcx
    11cf:       89 c7                   mov    edi,eax
    11d1:       e8 aa fe ff ff          call   1080 <read@plt>
    11d6:       0f b6 45 f3             movzx  eax,BYTE PTR [rbp-0xd]
    11da:       3c 42                   cmp    al,0x42
    11dc:       75 02                   jne    11e0 <main+0x57>
    11de:       eb fe                   jmp    11de <main+0x55>
    11e0:       b8 00 00 00 00          mov    eax,0x0
    11e5:       48 8b 55 f8             mov    rdx,QWORD PTR [rbp-0x8]
    11e9:       64 48 2b 14 25 28 00    sub    rdx,QWORD PTR fs:0x28
    11f0:       00 00 
    11f2:       74 05                   je     11f9 <main+0x70>
    11f4:       e8 77 fe ff ff          call   1070 <__stack_chk_fail@plt>
    11f9:       c9                      leave  
    11fa:       c3                      ret    
*/