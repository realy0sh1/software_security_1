# Please see RUNNING.md for details on how to use this Dockerfile.

##################################################################################################################
# The base image just pins the sources.
FROM debian:bookworm-20241016-slim@sha256:36e591f228bb9b99348f584e83f16e012c33ba5cad44ef5981a1d7c0a93eca22 AS default-base

# This ensures you don't accidentally update libc when you install things inside the container.
# If you're not planning on using `debug.yml` or otherwise installing things inside the container,
# and this causes problems, you can just remove it.
# See https://github.com/reproducible-containers/repro-sources-list.sh for more details.
RUN --mount=type=bind,source=docker-stuff/repro-sources-list.sh,target=/sbin/repro-sources-list.sh \
    /sbin/repro-sources-list.sh

# Add a user to run the services under. This is here since it has more side effects than the setup we do later,
# where we know what we need to copy.
RUN mkdir -p /softsec && \
    useradd -m user -d /softsec/user/

# Add a fake flag (we'll always need this, too).
RUN echo 'softsec{_On_the_server_this_fake_flag_will_be_replaced_with_a_real_flag_}' > /flag && \
    chmod 444 /flag

# We always want to run /softsec/entrypoint.sh.
ENTRYPOINT "/softsec/entrypoint.sh"

##################################################################################################################
# From this, build the base image for debugging (with glibc sources, GDB, pwndbg, etc.).
FROM default-base AS debug-base

# Enable the sources repository
RUN sed 's/^deb/deb-src/' /etc/apt/sources.list > /etc/apt/sources.list.d/deb-src.list

# Install GDB and (some) dependencies for pwndbg
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --yes \
        binutils dpkg-dev gdb git procps

# Grab glibc sources and set them up for use in GDB
WORKDIR /glibc
RUN apt-get source glibc && \
    mv glibc-*/ src && \
    echo 'directory /glibc/src' >> /root/.gdbinit

# Install pwndbg. The commit is the HEAD at the time I started setting this up, but can be overridden in the
# Compose file if necessary.
ARG PWNDBG_COMMIT=a2fa68f7edc8286d8e476046a4b68e7944d446b0
WORKDIR /pwndbg
RUN git init && \
    git remote add origin https://github.com/pwndbg/pwndbg && \
    git fetch --depth 1 origin ${PWNDBG_COMMIT} && \
    git checkout FETCH_HEAD

RUN ./setup.sh
ENV PWNDBG_NO_AUTOUPDATE=1

WORKDIR /

# Install a startup script that prints debugging instructions to the logs
COPY --chmod=0500 <<"EOF" /softsec/startup.sh
#!/bin/bash
if [ -e /.dockerenv ]; then CE="docker"; else CE="podman"; fi
echo -e "Use \x1b[1m${CE} ps\x1b[0m to find the name or ID of the current container."
echo -e "Use \x1b[1m${CE} exec -ti \x1b[34mCONTAINER\x1b[0m\x1b[1m /bin/bash\x1b[0m to start a root shell."
echo -e 'Connect to ynetd, then use \x1b[1mgdb -p "$(pgrep -n vuln)"\x1b[0m to start GDB.'
echo -e "Use \x1b[1m${CE} exec -ti "'"$('"${CE} ps -q -f 'ancestor=softsec/debug/practice-6'"$')" /bin/bash -c \'gdb -p "$(pgrep -n vuln)"\'\x1b[0m to do this in a single command.'
EOF

##################################################################################################################
# So far, this has all been task-agnostic. Now, add the current task to the base image.
FROM default-base AS default-intermediate

# Add all the dependencies
COPY docker-stuff/ynetd /softsec/
RUN chown -R root:root /softsec/ynetd /softsec/user && \
    chmod 500 /softsec/ynetd

# Add the vulnerable program
COPY vuln /softsec/user/
RUN chown root:root /softsec/user/vuln && \
    chmod 005 /softsec/user/vuln

# Add the entrypoint script
# First, if it exists, run /softsec/startup.sh to print instructions, then run ynetd.
COPY --chmod=0500 <<"EOF" /softsec/entrypoint.sh
#!/bin/bash
if [ -x /softsec/startup.sh ]; then /softsec/startup.sh; fi
exec /softsec/ynetd -u user -t "${YNETD_TIMEOUT}" -lt "${YNETD_TIMEOUT}" /softsec/user/vuln
EOF

# Paranoid sanity checks to find and remove setuid binaries and unexpectedly writable paths, don't worry about those.
RUN find / -ignore_readdir_race -type f \( -perm -4000 -o -perm -2000 \) -not -wholename /readflag -delete || true
USER user
RUN ! find / -writable -or -user $(id -un) -or -group $(id -Gn|sed -e 's/ / -or -group /g') 2> /dev/null \
    | grep -Ev -m 1 '^(/dev|/run|/proc|/sys|/tmp|/var/tmp|/var/lock|/var/mail|/var/spool/mail)(/|$)'
USER root

##################################################################################################################
# Update the debug image with the task itself and the required sources for debugging.
FROM debug-base AS debug-intermediate

# Copy the task setup in its entirety. TODO: This should use COPY --link, once podman supports it.
COPY --from=default-intermediate /softsec /softsec

# Copy the sources.
COPY vuln.cpp /

##################################################################################################################
# Finish up the debug and default images (with the default last, so it actually is the default)
FROM debug-intermediate AS debug
EXPOSE 1024
ENV YNETD_TIMEOUT=-1

FROM default-intermediate AS default
EXPOSE 1024
ENV YNETD_TIMEOUT=60
