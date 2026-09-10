// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

// Package webstatic serves the browser assets embedded in the openrun binary
// which are shared by every app on the server: the htmx runtime, the
// <log-tail> streaming log viewer, the action UI stylesheets and the brand
// fonts. They are served at URLPrefix with content-hashed file names and
// immutable caching, so one download is cached for all apps on a server,
// and the same URL works on every app domain. The route needs no
// authentication (no user data), and is mounted outside the transport-gated
// management API so it is available over plain HTTP too
package webstatic

import (
	"embed"
	"io/fs"
	"net/http"
	"path"

	"github.com/benbjohnson/hashfs"
)

// URLPrefix is the server route the shared assets are served under
const URLPrefix = "/_openrun/static"

//go:embed static/*
var embedded embed.FS

// FS is the hashed view of the embedded assets, rooted at the static dir
var FS = hashfs.NewFS(mustSub(embedded, "static"))

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

// URL returns the content-hashed URL of a shared asset, e.g.
// URL("logtail.js") = "/_openrun/static/logtail-<sha>.js". An unknown
// name is returned unhashed (the route then 404s, which surfaces the typo)
func URL(name string) string {
	return path.Join(URLPrefix, FS.HashName(name))
}

// Handler serves the shared assets; mount it at URLPrefix + "/*"
func Handler() http.Handler {
	return http.StripPrefix(URLPrefix, hashfs.FileServer(FS))
}
