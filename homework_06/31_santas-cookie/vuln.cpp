#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#define SANTA_UID 0
#define MAX_DECORATIONS 64

class Cookie
{
public:
    // virtual functions => subclasses can override it (see SantaSpecialCookie) 
    virtual void decorate()
    {
        printf("Decorating with regular ingredients!\n");
    }
};

class SantaSpecialCookie : public Cookie
{
public:
    virtual void decorate()
    {
        system("/usr/bin/cat /flag");
    }
};

struct CookieJar
{
    char decorations[MAX_DECORATIONS];
    Cookie cookie;
};

void make_festive(Cookie *cookie, const char *decorations)
{
    cookie->decorate();

    printf("Decorations used: ");
    write(1, decorations, MAX_DECORATIONS);
    printf("\n");
}

int main()
{
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    CookieJar jar;

    // Note: Privilege escalation is not part of the challenge
    if (SANTA_UID == getuid())
    {
        printf("Ho Ho Ho! Welcome back, Santa!\n");
        printf("Here's your special chocolate cookie batch!\n");
        jar.cookie = *(new SantaSpecialCookie());
    }

    printf("Santa likes a specific kind of cookie!\n");
    printf("Cookie decoration > ");
    // we can override frist 8 Byte of the cookie struct/class with is the pointer to the vtable
    // we must override to vtable of SantaSpecialCookie and are done :)
    read(0, jar.decorations, MAX_DECORATIONS + 8);

    make_festive(&jar.cookie, jar.decorations);
    return 0;
}
