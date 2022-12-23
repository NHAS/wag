LDFLAGS += -X 'github.com/NHAS/wag/config.Version=$(shell git describe --tags)'

LDFLAGS_RELEASE = $(LDFLAGS) -s -w

debug: .generate_ebpf
	go build -ldflags="$(LDFLAGS)"

release: .generate_ebpf
	go build -ldflags="$(LDFLAGS_RELEASE)"

docker:
	sudo docker run -u $(id -u) --rm -t -v `pwd`:/wag wag_builder

.generate_ebpf:
	BPF_CLANG=clang BPF_CFLAGS='-O2 -g -Wall -Werror' go generate ./...
