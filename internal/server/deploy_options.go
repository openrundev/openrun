// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import "github.com/openrundev/openrun/internal/types"

// The app deploy operations (create, reload, apply, preview, staged updates)
// share a set of flags and the git revision selection. They are passed as
// structs rather than positional args: a run of adjacent bools or strings
// lets a swapped argument compile and silently do the wrong thing (a dry run
// that promotes, a commit passed as the branch).

// GitRef selects the git revision to deploy from. Branch and Commit override
// the branch/commit recorded on the app (or the apply file source); empty
// keeps the recorded value. GitAuth names the git_auth entry to use, empty
// for the recorded one
type GitRef struct {
	Branch  string
	Commit  string
	GitAuth string
}

// DeployOptions are the common flags of the deploy operations. Not every
// operation uses every flag, each operation documents the ones it reads
type DeployOptions struct {
	Approve     bool // approve the plugin permissions the new code requests
	DryRun      bool // validate and report, nothing is committed
	Promote     bool // promote the staged change to prod
	ForceReload bool // reload even when the source is unchanged
	Verify      bool // verify the app (container start, health) before committing
}

// ApplyOptions are the options of a declarative apply: the deploy flags for
// the apps, the git revision of the apply file, and the apply specific
// settings
type ApplyOptions struct {
	DeployOptions
	Source  GitRef                // revision of the apply file's repo (a git apply path)
	Reload  types.AppReloadOption // which existing apps are reloaded
	Clobber bool                  // overwrite settings changed outside the apply file
	IsDev   bool                  // create new apps as dev apps
	// LastRunCommitId is the apply file commit of the previous sync run: the
	// apply is skipped when the source is unchanged (unless ForceReload)
	LastRunCommitId string
}

// createRequestGitRef is the git revision an app create or apply declaration
// asks for
func createRequestGitRef(req *types.CreateAppRequest) GitRef {
	return GitRef{Branch: req.GitBranch, Commit: req.GitCommit, GitAuth: req.GitAuthName}
}
