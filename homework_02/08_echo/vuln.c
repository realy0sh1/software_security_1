#include <err.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
