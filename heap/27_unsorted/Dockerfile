# To run this yourself, just run
#   docker compose up
# and connect with `nc 127.0.0.1 1024`
# You can also run this challenge manually, without Docker Compose:
#   docker build --platform linux/amd64 -t softsec/unsorted .
#   docker run --rm --platform linux/amd64 --cap-add SYS_ADMIN --security-opt apparmor=unconfined -p 127.0.0.1:1024:1024 -ti softsec/unsorted

FROM debian:bookworm-20241016-slim

# This ensures you don't accidentally update libc when you install things inside the container.
# If you're not planning on using `debug.yml` or otherwise installing things inside the container,
# and this causes problems, you can just remove it.
# See https://github.com/reproducible-containers/repro-sources-list.sh for more details.
# If you want to use GDB inside the container, make sure to add SYS_PTRACE to the list of capabilities.
RUN --mount=type=bind,source=docker-stuff/repro-sources-list.sh,target=/sbin/repro-sources-list.sh \
    /sbin/repro-sources-list.sh

# Add all the dependencies
RUN useradd -m user
COPY docker-stuff/ynetd /sbin/
RUN chown -R root:root /sbin/ynetd /home/user && \
    chmod 500 /sbin/ynetd

# Add the vulnerable program
COPY vuln /home/user
RUN chown root:root /home/user/vuln && \
    chmod 005 /home/user/vuln

# Paranoid sanity checks, don't worry about those.
RUN find / -ignore_readdir_race -type f \( -perm -4000 -o -perm -2000 \) -not -wholename /readflag -delete || true
USER user
RUN ! find / -writable -or -user $(id -un) -or -group $(id -Gn|sed -e 's/ / -or -group /g') 2> /dev/null | grep -Ev -m 1 '^(/dev|/run|/proc|/sys|/tmp|/var/tmp|/var/lock|/var/mail|/var/spool/mail)(/|$)'
USER root

RUN echo 'softsec{_On_the_server_this_fake_flag_will_be_replaced_with_a_real_flag_}' > /flag && \
    chmod 444 /flag

SHELL ["/bin/sh", "-c"]
EXPOSE 1024
ENV YNETD_TIMEOUT=60
CMD ynetd -u user -t "${YNETD_TIMEOUT}" -lt "${YNETD_TIMEOUT}" -se y -sh y "GLIBC_TUNABLES=glibc.malloc.tcache_count=0 /home/user/vuln"
