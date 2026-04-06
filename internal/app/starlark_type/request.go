// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package starlark_type

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"go.starlark.net/starlark"
)

// Request is a starlark.Value that represents an HTTP request. A Request is created from the Go http.Request
// and passed to the starlark handler function as it only argument. The Data field is updated with the handler's
// response and then the template evaluation is done with the same Request
type Request struct {
	AppName        string
	AppPath        string
	AppUrl         string
	PagePath       string
	PageUrl        string
	Method         string
	IsDev          bool
	IsPartial      bool
	PushEvents     bool
	HtmxVersion    string
	Headers        http.Header
	RemoteIP       string
	UrlParams      map[string]string
	Form           url.Values
	Query          url.Values
	PostForm       url.Values
	UserId         string
	CustomPerms    []string
	AppRBACEnabled bool
	Data           any
}

func (r Request) Attr(name string) (starlark.Value, error) {
	switch name {
	case "AppName":
		return starlark.String(r.AppName), nil
	case "AppPath":
		return starlark.String(r.AppPath), nil
	case "AppUrl":
		return starlark.String(r.AppUrl), nil
	case "PagePath":
		return starlark.String(r.PagePath), nil
	case "PageUrl":
		return starlark.String(r.PageUrl), nil
	case "Method":
		return starlark.String(r.Method), nil
	case "IsDev":
		return starlark.Bool(r.IsDev), nil
	case "IsPartial":
		return starlark.Bool(r.IsPartial), nil
	case "PushEvents":
		return starlark.Bool(r.PushEvents), nil
	case "HtmxVersion":
		return starlark.String(r.HtmxVersion), nil
	case "Headers":
		return MarshalStarlark(r.Headers)
	case "RemoteIP":
		return starlark.String(r.RemoteIP), nil
	case "UrlParams":
		return MarshalStarlark(r.UrlParams)
	case "Form":
		return MarshalStarlark(r.Form)
	case "Query":
		return MarshalStarlark(r.Query)
	case "PostForm":
		return MarshalStarlark(r.PostForm)
	case "UserId":
		return starlark.String(r.UserId), nil
	case "CustomPerms":
		return MarshalStarlark(r.CustomPerms)
	case "AppRBACEnabled":
		return starlark.Bool(r.AppRBACEnabled), nil
	case "Data":
		return MarshalStarlark(r.Data)
	default:
		return starlark.None, fmt.Errorf("request has no attribute '%s'", name)
	}
}

func (r Request) AttrNames() []string {
	return []string{"AppName", "AppPath", "AppUrl", "PagePath", "PageUrl", "Method", "IsDev", "IsPartial", "PushEvents", "HtmxVersion", "Headers", "RemoteIP", "UrlParams", "Form", "Query", "PostForm", "UserId", "CustomPerms", "AppRBACEnabled", "Data"}
}

func (r Request) String() string {
	return strings.ToLower(fmt.Sprintf("%s:%s:%s", r.AppName, r.PagePath, r.Method))
}

func (r Request) Type() string {
	return "Request"
}

func (r Request) Freeze() {
}

func (r Request) Truth() starlark.Bool {
	return r.AppName != ""
}

func (r Request) Hash() (uint32, error) {
	return starlark.Tuple{starlark.String(r.AppName), starlark.String(r.PagePath), starlark.String(r.Method), starlark.String(r.RemoteIP)}.Hash()
}

var _ starlark.Value = (*Request)(nil)
