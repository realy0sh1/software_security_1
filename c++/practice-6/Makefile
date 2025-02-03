vuln: vuln.cpp
	$(CXX) -std=c++20 -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=3 -fstack-protector-all -fstack-clash-protection -fcf-protection -pie -Og -g $^ -o $@

clean:
	$(RM) vuln

.PHONY: clean

