LDPATH ?= /usr/lib/x86_64-linux-gnu

vuln: vuln.o
	$(CC) -no-pie -Wl,-z,relro,-z,now -g -o $@ $^ -Wl,--push-state,--whole-archive,$(LDPATH)/libz.a,--pop-state

%.o: %.c
	$(CC) -no-pie -std=c99 -fno-stack-protector -O3 -g -c -o $@ $<

clean:
	$(RM) vuln vuln.o

.PHONY: clean
