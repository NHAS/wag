LDFLAGS += -X 'github.com/NHAS/wag/internal/config.Version=$(shell git describe --tags)'

LDFLAGS_RELEASE = $(LDFLAGS) -s -w

ID=$(shell id -u)
GID=$(shell id -g)

debug: .generate_ebpf 
	go build -ldflags="$(LDFLAGS)"

release: .generate_ebpf .build_ui
	go build -ldflags="$(LDFLAGS_RELEASE)"

docker:
	sudo docker run -u "$(ID):$(GID)" --rm -t -v `pwd`:/wag wag_builder

.generate_ebpf:
	BPF_CLANG=clang BPF_CFLAGS='-O2 -g -Wall -Werror' go generate ./...

.build_ui:
	cd ui/src; npm install; gulp build