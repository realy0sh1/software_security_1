RELRO_FLAGS   = -Wl,-z,relro,-z,now
STACK_FLAGS   = -fstack-protector-all -fstack-clash-protection
CET_FLAGS     = -fcf-protection
CXX_FLAGS     = -O2 -std=c++20 -g -fno-exceptions
W_FLAGS       = -Wall -Wextra -Wpedantic -Werror

vuln: vuln.cpp
	$(CXX) $(RELRO_FLAGS) $(STACK_FLAGS) $(CET_FLAGS) $(CXX_FLAGS) $(W_FLAGS) $^ -o $@

clean:
	$(RM) vuln

.PHONY: clean
