# To run this yourself:
#   docker build -t seashells .
#   echo 'flag{fake_flag}' > flag
#   docker run --rm --mount "type=bind,src=$(pwd)/flag,dst=/flag" --cap-add SYS_ADMIN --security-opt apparmor=unconfined -p 1024:1024 -ti seashells
# and connect with `nc 127.0.0.1 1024`
FROM debian:bookworm-slim

# Add all the dependencies
RUN useradd -m user
COPY docker-stuff/ynetd /sbin/
RUN chown -R root:root /sbin/ynetd /home/user && \
    chmod 500 /sbin/ynetd

# Add the shellcode runner
COPY docker-stuff/shellcode-runner /home/user/
RUN chown root:root /home/user/* && \
    chmod 005 /home/user/shellcode-runner

# Paranoid sanity checks, don't worry about those.
RUN find / -ignore_readdir_race -type f \( -perm -4000 -o -perm -2000 \) -not -wholename /readflag -delete || true
USER user
RUN ! find / -writable -or -user $(id -un) -or -group $(id -Gn|sed -e 's/ / -or -group /g') 2> /dev/null | grep -Ev -m 1 '^(/dev|/run|/proc|/sys|/tmp|/var/tmp|/var/lock|/var/mail|/var/spool/mail)(/|$)'
USER root

EXPOSE 1024
CMD cp /flag "/flag-$(tr -dc 'a-zA-Z0-9' </dev/urandom | head -c32)" && \
    chmod 000 /flag && \
    ynetd -u user -t 30 -lt 30 -sh y "/home/user/shellcode-runner -A"
