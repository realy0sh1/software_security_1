CXX = g++
CXXFLAGS = -fno-stack-protector -no-pie -g -O0 -std=c++11

vuln: vuln.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	$(RM) vuln

.PHONY: clean