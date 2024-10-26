vuln: vuln.c
	$(CC) -std=c99 -no-pie -fno-stack-protector -Wl,-z,execstack -Wall -Wextra -D_FORTIFY_SOURCE=0 -U_FORTIFY_SOURCE=0 $^ -o $@

clean:
	$(RM) vuln

.PHONY: clean

