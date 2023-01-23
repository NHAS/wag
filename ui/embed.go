package ui

import "embed"

//go:embed js/* css/* vendor/* img/*
var StaticContent embed.FS

//go:embed login.html template.html
//go:embed templates/*.html
var TemplatesContent embed.FS
