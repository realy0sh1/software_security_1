vuln: vuln.c
	$(CC) -pie -fno-plt -fstack-protector-all -fstack-clash-protection -fomit-frame-pointer -O1 -g -Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now -Wall -Wextra $^ -o $@

clean:
	$(RM) vuln

.PHONY: clean

