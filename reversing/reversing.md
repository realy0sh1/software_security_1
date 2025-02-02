# Reversing

## Installing IDA
- on sciebo: https://ruhr-uni-bochum.sciebo.de/s/HtOsjEyOgeYjLOd
- my key is in my keepass and needs to be saved in installation directory
- install IDA Free 9.0 (https://hex-rays.com/ida-free) in /opt/ida-free-pc-9.0
- add destop icon via /home/timniklas/.local/share/applications/ida.desktop
```
[Desktop Entry]
Name=IDA Free
Comment=Reverse Engineering
Exec=/opt/ida-free-pc-9.0/ida
Terminal=false
Type=Application
Icon=/opt/ida-free-pc-9.0/appico.png
StartupNotify=true
Categories=Development;
Keywords=IDA
```
- Show C-source code by pressing F5


### Using IDA
- 'F5' to decompile
- 'Tab' to switch between assembly and pseudocode
- 'Space' to swtich between graph view and linear view
- 'N' to rename things
- 'Y' to retype things
- 'x' to find cross references
- '/' to comment
- rightclick on value to change int->char etc
- mark -> edit -> export data (get hexstring from raw bytes)
- add (local) types, rightclick -> add type -> c code (then retype from char to phonebook pointer) 
```
struct phonebook_entry {
	char data[0x70];
}
```
