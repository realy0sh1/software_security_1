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
%42x     <-- we can just hardcode the length
%2$*1$d  <-- 

```
