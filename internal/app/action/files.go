// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// The values of a DOWNLOAD or IMAGE result are rows with the url of a file
// (and its name): a file registered with fs.serve_tmp_file, a static file of
// the app, or any other url. A browser fetches the url with the user's app
// session. The callers which have no app session (the CLI through the
// management API, MCP clients) get the file of an app local url through the
// app's own router, in-process, as the calling user: the rules the app
// applies to the url (the visibility and single access of served files) stay
// in force

// ErrFileTooLarge is the FileFetcher error for a file over the size limit.
// The file has not been consumed: a single access file can still be fetched
var ErrFileTooLarge = errors.New("file is larger than the size limit")

// FetchedFile is a file fetched from an app local url
type FetchedFile struct {
	Data     []byte
	MimeType string
}

// FileFetcher fetches an app local url (as returned by ResolveResultURL)
// through the app's router, as the identity in ctx. limit caps the file size
type FileFetcher func(ctx context.Context, localURL string, limit int64) (*FetchedFile, error)

// SetFileFetcher sets the fetcher used to inline result files (MCP)
func (a *Action) SetFileFetcher(fetcher FileFetcher) {
	a.fetchFile = fetcher
}

// ResolveResultURL resolves the url of a result row the way a browser showing
// the action page does: a relative url is relative to the action page. local
// is the server path (with the query) when the url is within the app; a url
// with a host, or one which resolves outside the app path, is external
func (a *Action) ResolveResultURL(rawURL string) (local string, external bool, err error) {
	ref, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || rawURL == "" {
		return "", false, fmt.Errorf("invalid result url %q", rawURL)
	}
	if ref.IsAbs() || ref.Host != "" {
		return "", true, nil
	}

	// The page of the root action is the app path with a trailing slash (the
	// bare app path redirects to it), other action pages have none
	pagePath := path.Join("/", a.appPath, a.actionPath)
	if a.actionPath == "" || a.actionPath == "/" {
		pagePath = strings.TrimSuffix(pagePath, "/") + "/"
	}
	resolved := (&url.URL{Path: pagePath}).ResolveReference(ref)
	resolved.Path = path.Clean(resolved.Path)

	appPath := path.Join("/", a.appPath)
	if appPath != "/" && resolved.Path != appPath && !strings.HasPrefix(resolved.Path, appPath+"/") {
		return "", true, nil
	}
	return resolved.RequestURI(), false, nil
}

// ResultFiles returns the files of a DOWNLOAD or IMAGE outcome: the rows
// which have a url
func ResultFiles(valuesMap []map[string]any) []ResultFile {
	files := []ResultFile{}
	for _, row := range valuesMap {
		fileURL, _ := row["url"].(string)
		if fileURL == "" {
			continue
		}
		name, _ := row["name"].(string)
		files = append(files, ResultFile{Name: name, URL: fileURL})
	}
	return files
}

// ResultFile is a file row of a DOWNLOAD or IMAGE result
type ResultFile struct {
	Name string
	URL  string
}
