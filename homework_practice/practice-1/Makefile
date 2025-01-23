vuln: vuln.c
	$(CC) -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=3 -fstack-clash-protection -fcf-protection -pie -Og -g $^ -o $@

