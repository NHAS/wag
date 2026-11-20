module github.com/NHAS/wag

go 1.27.4

require (
	github.com/NHAS/autoetcdtls v0.0.0-20240225231227-9d5906c5b4f2
	github.com/NHAS/session v0.0.0-20241210092238-534610261793
	github.com/NHAS/tetcd v0.0.60-beta
	github.com/NHAS/webauthn v0.0.0-20240606085832-ea3172ef4dfa
	github.com/caddyserver/certmagic v0.25.6
	github.com/coder/websocket v1.8.15
	github.com/coreos/go-iptables v0.8.0
	github.com/gaissmai/bart v0.30.0
	github.com/go-playground/validator/v10 v10.30.6
	github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674
	github.com/libdns/cloudflare v0.2.2
	github.com/mattn/go-sqlite3 v1.14.53
	github.com/mdlayher/netlink v1.11.2
	github.com/msteinert/pam v1.2.0
	github.com/pquerna/otp v1.5.0
	github.com/rs/zerolog v1.35.1
	github.com/stretchr/testify v1.12.1
	github.com/zitadel/oidc/v3 v3.52.0
	go.etcd.io/etcd/client/pkg/v3 v3.7.4
	go.etcd.io/etcd/client/v3 v3.7.4
	go.etcd.io/etcd/server/v3 v3.7.3
	golang.org/x/crypto v0.59.0
	golang.org/x/exp v0.0.0-20261113113407-e3970619a1a4
	golang.org/x/net v0.63.0
	golang.org/x/sys v0.50.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	tailscale.com v1.104.7
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/boombuler/barcode v1.1.0 // indirect
	github.com/caddyserver/zerossl v0.1.6 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.7.0 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/fxamacker/cbor/v2 v2.10.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.16 // indirect
	github.com/go-jose/go-jose/v4 v4.1.9 // indirect
	github.com/go-json-experiment/json v1.27.2 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-playground/locales v0.14.2 // indirect
	github.com/go-playground/universal-translator v0.18.2 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus v1.1.1 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.3.4 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.34.0 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/klauspost/cpuid/v2 v2.4.2 // indirect
	github.com/leodido/go-urn v1.5.0 // indirect
	github.com/libdns/libdns v1.1.1 // indirect
	github.com/mattn/go-colorable v0.1.16 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mdlayher/genetlink v1.4.0 // indirect
	github.com/mdlayher/socket v0.8.0 // indirect
	github.com/mholt/acmez/v3 v3.1.7 // indirect
	github.com/miekg/dns v1.1.73 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/muhlemmer/gu v0.3.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pandatix/go-abnf v0.5.5 // indirect
	github.com/prometheus/client_golang v1.25.0 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.74.0 // indirect
	github.com/prometheus/procfs v0.23.0 // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	github.com/soheilhy/cmux v0.1.5 // indirect
	github.com/spf13/pflag v1.1.0 // indirect
	github.com/tmc/grpc-websocket-proxy v0.0.0-20220101234140-673ab2c3ae75 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xiang90/probing v0.0.0-20221125231312-a49e3df8f510 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	github.com/zitadel/schema v1.3.2 // indirect
	go.etcd.io/bbolt v1.5.0 // indirect
	go.etcd.io/etcd/api/v3 v3.7.4 // indirect
	go.etcd.io/etcd/pkg/v3 v3.7.3 // indirect
	go.etcd.io/raft/v3 v3.7.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.72.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.47.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.47.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/sdk v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	go.yaml.in/yaml/v2 v2.4.5 // indirect
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	golang.org/x/oauth2 v0.38.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20261118221215-c8830f628b3f // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261118221215-c8830f628b3f // indirect
	google.golang.org/grpc v1.85.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	k8s.io/utils v0.0.0-20261023123148-ca04ba58ecab // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)

replace golang.zx2c4.com/wireguard => github.com/NHAS/wireguard-go v0.0.0-20250612003640-64654948f25c
