# How to run this task

This task ships with Compose files to provide a somewhat reproducible setup. These have been tested with both Docker and Podman.

### Getting Started

To run the "default" configuration, simply use `docker compose up` or `podman compose up`.
To run the task in debug mode, use `docker compose -f debug.yml up` or `podman compose -f debug.yml up`.

### Connecting

Once the container is running, you can connect to your local instance using `nc 127.0.0.1 1024`.
This should connect you directly to the task.

### Manual Build

If you really don't want to use Compose, you can also use the Dockerfile manually (using either Docker or Podman).
To build and run the default images with Docker, use the following commands (the Podman commands should be equivalent):

    docker build --platform linux/amd64 -t softsec/practice-6 .
    docker run --rm --platform linux/amd64 --cap-add SYS_ADMIN --security-opt apparmor=unconfined -p 127.0.0.1:1024:1024 -ti softsec/practice-6

To use the debug mode, specify `--target debug` while building the image (and use a different image name, e.g. `softsec/debug/practice-6`):

    docker build --platform linux/amd64 --target debug -t softsec/debug/practice-6 .
    docker run --rm --platform linux/amd64 --cap-add SYS_ADMIN --cap-add SYS_PTRACE --security-opt apparmor=unconfined -p 127.0.0.1:1024:1024 -ti softsec/debug/practice-6

### Debugging

To debug in the container, run the task in debug mode (using `-f debug.yml`).
The output will contain instructions on how to connect to the task; for completeness, the general details are also included here:

 1. Use `docker ps` to find the name or ID of the container (typically, `softsec-practice-6`).
 2. Use `docker exec -ti <container> /bin/bash` to start a root shell in the container.
 3. Connect to ynetd, then use `gdb -p "$(pgrep -n vuln)"` to start GDB and attach it to the task.

You can also do this in a single command using a filter on the image name in `docker ps`:

    docker exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-6')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

If you use Podman without the Docker CLI compatiblity layer, simply replace `docker` with `podman` in all of these commands.

### Additional Notes

These files use the Compose service `extends` key to actually configure the base service declared in `base.yml`.
You should not run `base.yml` directly. In practice, this should use Compose profiles instead, but there
is currently no way to set a default profile that works with `podman-compose`. This is podman-compose issue
[#797](https://github.com/containers/podman-compose/issues/797).

In `podman compose`, handling of ^C is a little wonky: Instead of stopping the containers like with `docker compose`, they
will continue to run in the background (despite messages that might tell you otherwise). In either case, you should explicitly
stop and remove the containers using `docker compose down` or `podman compose down`.
