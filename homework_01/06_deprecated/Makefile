vuln: vuln.c
	$(CC) -std=c99 -pie -fno-stack-protector -Wl,-z,execstack -Wall -Wextra $^ -o $@

clean:
	$(RM) vuln

.PHONY: clean

