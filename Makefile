LDFLAGS += -X 'github.com/NHAS/wag/internal/config.Version=$(shell git describe --tags)'

LDFLAGS_RELEASE = $(LDFLAGS) -s -w

ID=$(shell id -u)
GID=$(shell id -g)


goonly:
	go build -ldflags="$(LDFLAGS)"

debug:  .build_ui
	go build -ldflags="$(LDFLAGS)"

release: .build_ui
	go build -ldflags="$(LDFLAGS_RELEASE)"

dev:	debug
	sudo docker compose -f docker-compose.dev.yml up 

docker:
	sudo docker run -u "$(ID):$(GID)" --rm -t -v `pwd`:/wag wag_builder

.build_ui:
	cd adminui/src; npm install; gulp build
