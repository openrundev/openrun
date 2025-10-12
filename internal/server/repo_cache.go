// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport" // for AuthMethod
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/go-git/go-git/v5/storage/memory"
)

type Repo struct {
	url    string
	branch string
	commit string
	auth   string
}

type CacheDir struct {
	dir           string
	commitMessage string
	hash          string
}

type RepoCache struct {
	server   *Server
	rootDir  string
	cache    map[Repo]CacheDir
	shaCache map[Repo]string // Cache for commit hashes
}

func NewRepoCache(server *Server) (*RepoCache, error) {
	tmpDir, err := os.MkdirTemp("", "openrun_git_")
	if err != nil {
		return nil, err
	}
	return &RepoCache{
		server:   server,
		rootDir:  tmpDir,
		cache:    make(map[Repo]CacheDir),
		shaCache: make(map[Repo]string),
	}, nil
}

func (r *RepoCache) GetSha(sourceUrl, branch, gitAuth string) (string, error) {
	gitAuth = cmp.Or(gitAuth, r.server.config.Security.DefaultGitAuth)
	authEntry, err := r.server.loadGitKey(gitAuth)
	if err != nil {
		return "", err
	}

	// Figure on which repo to clone
	repo, _, err := parseGitUrl(sourceUrl, authEntry.usingSSH)
	if err != nil {
		return "", err
	}

	// Check if we have the commit in cache
	if sha, ok := r.shaCache[Repo{repo, branch, "", gitAuth}]; ok {
		return sha, nil
	}

	var auth transport.AuthMethod
	if gitAuth != "" {
		r.server.Info().Msgf("Using git auth %s", gitAuth)
		auth, err = r.createAuthMethod(gitAuth)
		if err != nil {
			return "", err
		}
	}

	sha, err := latestCommitSHA(repo, branch, auth)
	if err != nil {
		return "", err
	}
	r.shaCache[Repo{repo, branch, "", gitAuth}] = sha
	return sha, nil
}

func (r *RepoCache) createAuthMethod(gitAuth string) (transport.AuthMethod, error) {
	authEntry, err := r.server.loadGitKey(gitAuth)
	if err != nil {
		return nil, err
	}

	if len(authEntry.key) != 0 {
		// SSH auth
		return ssh.NewPublicKeys(authEntry.user, authEntry.key, authEntry.password)
	} else {
		// HTTP auth, either basic or using Personal Access Token
		return &http.BasicAuth{
			Username: authEntry.user,
			Password: authEntry.password,
		}, nil
	}
}

func latestCommitSHA(repoURL, branch string, auth transport.AuthMethod) (string, error) {
	remoteCfg := &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	}
	remote := git.NewRemote(memory.NewStorage(), remoteCfg)

	refs, err := remote.List(&git.ListOptions{
		Auth: auth,
	})
	if err != nil {
		return "", fmt.Errorf("could not list remote refs: %w", err)
	}

	want := plumbing.NewBranchReferenceName(branch) // e.g. "refs/heads/main"
	for _, ref := range refs {
		if ref.Name() == want {
			return ref.Hash().String(), nil
		}
	}

	return "", fmt.Errorf("branch %q not found", branch)
}

func (r *RepoCache) CheckoutRepo(sourceUrl, branch, commit, gitAuth string, isDev bool) (string, string, string, string, error) {
	gitAuth = cmp.Or(gitAuth, r.server.config.Security.DefaultGitAuth)
	authEntry, err := r.server.loadGitKey(gitAuth)
	if err != nil {
		return "", "", "", "", err
	}

	// Figure on which repo to clone
	repo, folder, err := parseGitUrl(sourceUrl, authEntry.usingSSH)
	if err != nil {
		return "", "", "", "", err
	}

	repoKey := Repo{repo, branch, commit, gitAuth}
	dir, ok := r.cache[repoKey]
	if ok {
		return dir.dir, folder, dir.commitMessage, dir.hash, nil
	}

	cloneOptions := git.CloneOptions{
		URL: repo,
	}

	if commit == "" {
		// No commit id specified, checkout specified branch
		cloneOptions.ReferenceName = plumbing.NewBranchReferenceName(branch)
		cloneOptions.SingleBranch = true
		if !isDev {
			cloneOptions.Depth = 1
		}
	}

	if gitAuth != "" {
		r.server.Info().Msgf("Using git auth %s", gitAuth)
		auth, err := r.createAuthMethod(gitAuth)
		if err != nil {
			return "", "", "", "", err
		}
		cloneOptions.Auth = auth
	}

	var targetPath string
	if isDev {
		// We don't have a previous dev checkout for this repo, create a new one
		repoName := filepath.Base(repo)
		targetPath = getUnusedRepoPath(os.ExpandEnv("$OPENRUN_HOME/app_src/"), repoName)
		if err := os.MkdirAll(targetPath, 0744); err != nil {
			return "", "", "", "", err
		}
	} else {
		targetPath, err = os.MkdirTemp(r.rootDir, "repo_")
		if err != nil {
			return "", "", "", "", err
		}
	}

	// Configure the repo to Clone
	r.server.Info().Msgf("Cloning git repo %s to %s", repo, targetPath)
	gitRepo, err := git.PlainClone(targetPath, false, &cloneOptions)
	if err != nil {
		return "", "", "", "", fmt.Errorf("error checking out branch %s: %w", branch, err)
	}

	w, err := gitRepo.Worktree()
	if err != nil {
		return "", "", "", "", err
	}
	// Checkout specified hash
	options := git.CheckoutOptions{}
	if commit != "" {
		r.server.Info().Msgf("Checking out commit %s", commit)
		options.Hash = plumbing.NewHash(commit)
	} else {
		options.Branch = plumbing.NewBranchReferenceName(branch)
	}

	/* Sparse checkout seems to not be reliable with go-git
	if folder != "" {
		options.SparseCheckoutDirectories = []string{folder}
	}
	*/
	if err := w.Checkout(&options); err != nil {
		return "", "", "", "", fmt.Errorf("error checking out branch %s commit %s: %w", branch, commit, err)
	}

	ref, err := gitRepo.Head()
	if err != nil {
		return "", "", "", "", err
	}
	newCommit, err := gitRepo.CommitObject(ref.Hash())
	if err != nil {
		return "", "", "", "", err
	}

	// Save the repo in cache
	r.cache[Repo{repo, branch, commit, gitAuth}] = CacheDir{
		dir:           targetPath,
		commitMessage: newCommit.Message,
		hash:          newCommit.Hash.String(),
	}

	return targetPath, folder, newCommit.Message, newCommit.Hash.String(), nil
}

func getUnusedRepoPath(targetDir, repoName string) string {
	if _, err := os.Stat(path.Join(targetDir, repoName)); os.IsNotExist(err) {
		return path.Join(targetDir, repoName)
	}
	count := 2
	for {
		unusedName := fmt.Sprintf("%s%d", repoName, count)
		if _, err := os.Stat(path.Join(targetDir, unusedName)); os.IsNotExist(err) {
			return path.Join(targetDir, unusedName)
		}
		count++
	}
}

func (r *RepoCache) Cleanup() {
	if r.rootDir != "" {
		os.RemoveAll(r.rootDir) //nolint:errcheck
		r.rootDir = ""
	}
}
