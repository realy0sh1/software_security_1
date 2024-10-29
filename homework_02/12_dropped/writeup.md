# Player
- Tim Niklas Gruel 1080 2021 2831
- username: realy0sh1

# Writeup: "dropped"
- story:  no story :/
- the binary has: -fno-stack-protector -no-pie => that means no canarie and no ASLR for the binray
- I found gadgets with
```
ropper --file ./vuln
```
- find global offset table (IDA->View->OpenSubviews->Segments->.got): "read" offset is at 0000000000403FE8


0x0000000000401004: mov rax, qword ptr [rip + 0x2fed]; test rax, rax; je 0x1012; call rax;

403FF1


0x731d38b14853

0xc35ec35f