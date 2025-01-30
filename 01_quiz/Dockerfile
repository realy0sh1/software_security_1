# To run this yourself:
#   docker build -t quiz .
#   echo 'flag{fake_flag}' > flag
#   docker run --rm --mount "type=bind,src=$(pwd)/flag,dst=/flag" --cap-add SYS_ADMIN --security-opt apparmor=unconfined -p 1024:1024 -ti quiz
# and connect with `nc 127.0.0.1 1024`
FROM debian:bookworm-slim

# We need Python
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 && \
    rm -rf /var/lib/apt/lists

# Add all the dependencies
RUN useradd -m user
COPY docker-stuff/ynetd /sbin/
RUN chown -R root:root /sbin/ynetd /home/user && \
    chmod 500 /sbin/ynetd

# Add the quiz
COPY quiz.py questions.json /home/user/
RUN chown root:root /home/user/quiz.py && \
    chmod 004 /home/user/questions.json && \
    chmod 005 /home/user/quiz.py

# Paranoid sanity checks, don't worry about those.
RUN find / -ignore_readdir_race -type f \( -perm -4000 -o -perm -2000 \) -not -wholename /readflag -delete || true
USER user
RUN ! find / -writable -or -user $(id -un) -or -group $(id -Gn|sed -e 's/ / -or -group /g') 2> /dev/null | grep -Ev -m 1 '^(/dev|/run|/proc|/sys|/tmp|/var/tmp|/var/lock|/var/mail|/var/spool/mail)(/|$)'
USER root

EXPOSE 1024
CMD ynetd -u user -t 120 -lt 120 /home/user/quiz.py
