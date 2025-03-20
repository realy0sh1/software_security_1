import pwn

target = "88F940A0FDF8B09C 991E02A4DE5847F D9"

target_bytes = pwn.p64(0x88F940A0FDF8B09C) + pwn.p64(0x991E02A4DE5847F) + b'\xD9'

target = [byte for byte in target_bytes]
print(target_bytes.hex())
print(target)
print(type(target))

# possible chars
possible_chars = [char for char in range(20, 176)]


# each char in input flag must match target after transformation, just do brute force

flag = []
for pos in range(17):
    # guess next char
    print(flag)
    found = False
    for guess in possible_chars:
        candidate_flag = flag + [guess]
        v8 = 66
        for i, v in enumerate(candidate_flag):
            v5 = v
            v4 = v8 & 7
            v4 &= 0xFF
            v5 = ((v5 << v4)) | (v5 >> ((8 - v4) & 0xFF))
            v5 += 7 * i + 13
            v5 ^= v8
            v5 &= 0xFF
            v8 += v5
            v8 &= 0xFF


            if v5 != target[i]:
                break
            else:
                if i == pos:
                    flag = candidate_flag
                    found = True
                    break
        if found: break
flag = "".join([chr(c) for c in flag])
print(flag)

