package resources

import (
	"embed"
)

//go:embed frontend/dist/*
var Static embed.FS
