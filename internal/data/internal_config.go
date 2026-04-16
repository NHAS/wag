package data

//go:generate go run github.com/NHAS/tetcd/cmd/tetcd-gen -type=github.com/NHAS/wag/internal/config.Config -out=config_etcd.go -prefix=wag-config

//go:generate go run github.com/NHAS/tetcd/cmd/tetcd-gen -type=github.com/NHAS/wag/internal/config.InternalConfig -out=config_internal_etcd.go -prefix=wag-config-internal
