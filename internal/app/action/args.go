// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"fmt"

	"go.starlark.net/starlark"
)

// Args is a starlark.Value that represents the arguments being passed to the Action handler. It contains value for the params.
type Args struct {
	members starlark.StringDict
}

// NewArgs builds an Args value from the given members
func NewArgs(members starlark.StringDict) *Args {
	return &Args{members: members}
}

func (a *Args) Attr(name string) (starlark.Value, error) {
	v, ok := a.members[name]
	if !ok {
		return starlark.None, fmt.Errorf("Args has no attribute '%s'", name)
	}

	return v, nil
}

func (a *Args) AttrNames() []string {
	return a.members.Keys()
}

func (a *Args) String() string {
	return a.members.String()
}

func (a *Args) Type() string {
	return "Args"
}

func (a *Args) Freeze() {
}

func (a *Args) Truth() starlark.Bool {
	return true
}

func (a *Args) Hash() (uint32, error) {
	return 0, fmt.Errorf("Hash not implemented for Args")
}

var _ starlark.Value = (*Args)(nil)
