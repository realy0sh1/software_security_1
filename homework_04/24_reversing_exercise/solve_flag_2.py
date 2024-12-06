# input must be 34 bytes + zero byte long (string has 35 bytes)

# 0x37 is xored on uneven index in array
# 0x13 is xored on even index in array
# this has to be false: *(_QWORD *)guessed_flag ^ 0x4C70526043755860LL | *(_QWORD *)(guessed_flag + 8) ^ 0x444C4E6152656872LL
# this has to be false: *(_QWORD *)(guessed_flag + 16) ^ 0x586B68765B635A7ALL | *(_QWORD *)(guessed_flag + 24) ^ 0x5B635A724F766861LL
# this has to be false: *(_DWORD *)(guessed_flag + 31) != 0x4A765B


# 35 Bytes long
# char  0 -  7 must be 0x4C70526043755860
chars_0_until_7  = 0x4C70526043755860
chars_0_until_7 ^= 0x3713371337133713
print(bytes.fromhex(hex(chars_0_until_7)[2:]))

# char  8 - 15 must be 0x444C4E6152656872
chars_8_until_15 = 0x444C4E6152656872
chars_8_until_15 ^= 0x3713371337133713

# char 16 - 23 must be 0x586B68765B635A7A
chars_16_until_23 = 0x586B68765B635A7A
chars_16_until_23 ^= 0x3713371337133713

# char 24 - 31 must be 0x5B635A724F766861
char_24_until_32 = 0x5B635A724F766861
char_24_until_32 ^= 0x3713371337133713

# char 32 - 34 must be 0x4A76
char_32_until_43 = 0x4A76
char_32_until_43 ^= 0x3713

flag = bytes.fromhex( hex(char_32_until_43)[2:] + hex(char_24_until_32)[2:] + hex(chars_16_until_23)[2:] + hex(chars_8_until_15)[2:] + hex(chars_0_until_7)[2:])
print(flag[::-1])
