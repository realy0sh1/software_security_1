vuln: vuln.c
	$(CC) -fno-stack-protector -no-pie -Wl,-z,relro,-z,now -O3 -g $^ -o $@
