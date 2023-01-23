package ui

import "embed"

//go:embed js/* css/* vendor/* img/*
var staticContent embed.FS

//go:embed login.html template.html
//go:embed templates/*.html
var templatesContent embed.FS
