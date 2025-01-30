# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "echo"
- story:  no story :/
- extract linker from docker file to run the correct libc locally
```
docker compose up
docker ps
docker exec -it c93ecb781483 /bin/bash
cd /lib/x86_64-linux-gnu
docker cp c93ecb781483:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /home/timniklas/Code/software_security_1/homework_02/10_echo
```
- use pwninit to get started and so setup
```
pwninit
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
- below are format strings that are allowed (basically everything allowed)
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

## 2) exploit
- i write a ropchain onto the stack at return address of c's main()
- then i send EOF, to finish c program
- this executes my rop chain
- i leaked addresses via format string first
- we can use the format string + buffer to write to arbitrary memory
    - write address we want to write to into buffer
    - then we reference that buffer address via high input value => is interpreted as pointer => write to arbitrary memory
- code:
```python

```
- flag
```
softsec{qI_y8Nh6lXNCEBiyCZSuP_raN3LKqprPrebeNHBUVHZNFwR8cVnSl05D40EZidOL}
```

## 3) Optional
- we can override the .got address and point printf to system()
- this is possible because: partial RELRO (override .got)

