vuln: vuln.c
	gcc -O2 -Wall -Wextra -Wpedantic -Wl,-z,lazy -D_FORTIFY_SOURCE=0 -fstack-protector-all -pie $< -o $@
