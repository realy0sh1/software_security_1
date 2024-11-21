# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "yellow-pages"
- story: Following your detailed feedback, we've redesigned our software. Also, we've rebranded so we don't have to pay the bug bounties.Could you test the software again, please?

# setup
```
pwninit
```

# overview:
- phonebook entry before:
```
struct phonebook_entry {
    char phone_number[32];
    char name[64];
    struct phonebook_entry *next;
    struct phonebook_entry *prev;
};
```
- phonebook entry now:
```
struct phonebook_entry {
    struct phonebook_entry *next;
    struct phonebook_entry *prev;
    char phone_number[32];
    char name[48];
};
```
- idea: if two phonebook entries are right after each other in heap -> override 2nd one


- we can print value of *phonebook in gdb via:
```
print *phonebook
```
```
pwndbg> print *phonebook
$2 = {
  next = 0x577fe0f932a0,
  prev = 0x0,
  phone_number = "42", '\000' <repeats 29 times>,
  name = "attacker", '\000' <repeats 39 times>
}
```
```
telescope 0x577fe0f932a0 30
```
```
pwndbg> telescope 0x577fe0f932a0 30
00:0000│  0x577fe0f932a0 ◂— 0
01:0008│  0x577fe0f932a8 —▸ 0x577fe0f93310 —▸ 0x577fe0f932a0 ◂— 0
02:0010│  0x577fe0f932b0 ◂— 0x37333331 /* '1337' */
03:0018│  0x577fe0f932b8 ◂— 0
... ↓     2 skipped
06:0030│  0x577fe0f932d0 ◂— 'realy0sh1'
07:0038│  0x577fe0f932d8 ◂— 0x31 /* '1' */
08:0040│  0x577fe0f932e0 ◂— 0
... ↓     4 skipped
0d:0068│  0x577fe0f93308 ◂— 0x71 /* 'q' */
0e:0070│  0x577fe0f93310 —▸ 0x577fe0f932a0 ◂— 0
0f:0078│  0x577fe0f93318 ◂— 0
10:0080│  0x577fe0f93320 ◂— 0x3234 /* '42' */
11:0088│  0x577fe0f93328 ◂— 0
... ↓     2 skipped
14:00a0│  0x577fe0f93340 ◂— 'attacker'
15:00a8│  0x577fe0f93348 ◂— 0
... ↓     5 skipped
1b:00d8│  0x577fe0f93378 ◂— 0x20c91
1c:00e0│  0x577fe0f93380 ◂— 0
1d:00e8│  0x577fe0f93388 ◂— 0
```
- flag
```
softsec{i2awvUXtBdhyS_Y7QwJtcG-U7x6EoRqY8EB7CsPA7W4njoe3tOTNfvuZM2s9zHqC}
```