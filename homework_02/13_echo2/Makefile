TASK=softsec-ws23-$(shell basename "$(CURDIR)")

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	TAR=tar
	RMDIR=rmdir
endif
ifeq ($(UNAME_S),Darwin)
	TAR=gtar
	RMDIR=grmdir
endif

RELRO_FLAGS   = -Wl,-z,relro,-z,now
STACK_FLAGS   = -fstack-protector-all -fstack-clash-protection
CET_FLAGS     = -fcf-protection
C_FLAGS       = --std=c11 -O2 -D_FORTIFY_SOURCE=1
W_FLAGS       = -Wall -Wextra -Wpedantic

%: %.c
	$(CC) $(RELRO_FLAGS) $(STACK_FLAGS) $(CET_FLAGS) $(C_FLAGS) $(W_FLAGS) $^ -o $@

.PHONY: clean
clean:
	$(RM) vuln

.PHONY: docker
docker:
	docker build --tag $(TASK):latest --platform linux/amd64 . --load

.PHONY: extract
extract:
	docker build --tag $(TASK):build --platform linux/amd64 -f Dockerfile.build . --load
	docker run --rm --platform linux/amd64 $(TASK):build > ./vuln

.PHONY: docker
run: docker
	docker run \
		-ti \
		--rm \
		--mount "type=bind,src=$(CURDIR)/flag,dst=/flag" \
		--cap-add SYS_ADMIN \
		--security-opt apparmor=unconfined \
		-p 1024:1024 \
		--platform linux/amd64 \
		$(TASK):latest
