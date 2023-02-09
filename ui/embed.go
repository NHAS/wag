package ui

import "embed"

//go:embed js/* css/* vendor/* img/* fonts/*
var staticContent embed.FS

//go:embed templates/*
//go:embed templates/management/*
//go:embed templates/diagnostics/*
//go:embed templates/policy/*
//go:embed templates/settings/*
var templatesContent embed.FS
