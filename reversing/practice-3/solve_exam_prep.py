#!/usr/bin/env python3

# reversing
import pwn
import string

# flag needs to be 17 chars long
v2 = pwn.p64(0x88F940A0FDF8B09C) + pwn.p64(0x991E02A4DE5847F) + b'\xD9'

# we can brute force flag byte by byte
flag = ''

# this is one byte, so mod 256
v8_so_far = 66
for i in range(17):

    # guess the correct next v5
    for v5_guess in [char for char in range(20, 176)]:
        v8 = v8_so_far
        v5 = v5_guess#pwn.u8(v5_guess.encode())
        v4 =  v8 & 7
        v4 %= 256
        v5 = (v5 << v4) | (v5 >> ((8 - v4)%256))
        v5 += (7 * i + 13)
        v5 ^= v8
        v5 %= 256
        v8 += v5
        v8 %= 256

        if v5 == v2[i]:
            flag += chr(v5_guess)
            print(flag)
            v8_so_far = v8
            break
print(flag)