RELRO_FLAGS   = -Wl,-z,relro,-z,now
STACK_FLAGS   = -fstack-protector-all -fstack-clash-protection
CPP_FLAGS     = -D_FORTIFY_SOURCE=3
CET_FLAGS     = -fcf-protection
C_FLAGS       = -O2 -std=gnu17 -g
W_FLAGS       = -Wall -Wextra -Werror

vuln: vuln.c
	$(CC) $(RELRO_FLAGS) $(STACK_FLAGS) $(CPP_FLAGS) $(CET_FLAGS) $(C_FLAGS) $(W_FLAGS) $^ -o $@

clean:
	$(RM) vuln

.PHONY: clean
