vuln: vuln.c
	$(CC) -fcf-protection=none -g -D_FORTIFY_SOURCE=0 -fno-stack-protector -no-pie $^ -o $@

clean:
	$(RM) vuln

.PHONY: clean
