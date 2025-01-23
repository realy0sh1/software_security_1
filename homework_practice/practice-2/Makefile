vuln: vuln.S
	$(CC) -no-pie -nostdlib -Wl,-z,relro,-z,now,-z,noexecstack -O3 -g $^ -o $@
