LDFLAGS += -X 'github.com/NHAS/wag/commands.Version=$(shell git describe --tags)'

LDFLAGS_RELEASE = $(LDFLAGS) -s -w

debug: .generate_ebpf
	go build -ldflags="$(LDFLAGS)"

release: .generate_ebpf
	go build -ldflags="$(LDFLAGS_RELEASE)"

.generate_ebpf:
	BPF_CLANG=clang BPF_CFLAGS='-O2 -g -Wall -Werror' go generate ./..