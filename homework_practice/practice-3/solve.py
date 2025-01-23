import pwn

# Feedback: I am not sure if this is solution is inteded, but it works. The reversing amount was reasonable. Still it is not a nice task to reverse a flag. Took me roughly 2 hours, because it missed that char overflows

# flag has 17 chars

# ! flip endieness
encrypted_flag = [0x9C,0xB0,0xF8,0xFD,0xA0,0x40,0xF9,0x88,0x7F,0x84,0xE5,0x4D,0x2A,0xE0,0x91,0x09,0xD9]

"""
k = 66
# i = 0...16
for i in range(17):
    c = guessed_flag[i]

    # only look at last 7 bits of v8, so mod 8
    encrypted_char_at_index = (c << (k %8)) | (c >> (8 - (k % 8) ))
    encrypted_char_at_index += 7*i+13
    encrypted_char_at_index ^= k
    k += encrypted_char_at_index

    if k != encrypted_flag[i]:
        print("wrong flag")
    
print("correct flag")
"""

# as this is iterative and there are only 256 options per char, we can do exhaustive search ;)
correct_input_flag = ""

for pos in range(1,18):
    found = False
    for candidate in range(32,127):
        # check if 0...pos is correct
        candidate_flag = correct_input_flag + chr(candidate)

        k = 66
        for i in range(pos):
            c = ord(candidate_flag[i])
            encrypted_char_at_index = ((c << (k %8))&0xFF) | ((c >> (8 - (k % 8) ))&0xFF)
            encrypted_char_at_index += 7*i+13
            encrypted_char_at_index ^= k
            encrypted_char_at_index &= 0xFF
            k += encrypted_char_at_index
            k &= 0xFF
            if (encrypted_char_at_index == encrypted_flag[i]) and (i == pos-1):
                # found correct char
                correct_input_flag += chr(candidate)
                found = True
                break
        
        if found: break

# time_flies_right?
# nc tasks.ws24.softsec.rub.de 33260
# softsec{rCF3b4zuSDR-7eDShXxPDN2hq2A5JY7ogyH4syVE4QSoCBEg0gTsXkIpaR9uJiXC}
