// Package main wires together the HTTPS gateway, dashboard handlers, and embedded assets.
package main

import "embed"

//go:embed static/*
var staticFiles embed.FS
