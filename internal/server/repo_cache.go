// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
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
	folder string
	// isDev distinguishes dev checkouts (long-lived, under $OPENRUN_HOME/app_src)
	// from prod checkouts (temp dirs removed on Cleanup), so a dev app never
	// gets handed a temp checkout that is about to be deleted.
	isDev bool
}

type CacheDir struct {
	dir           string
	commitMessage string
	hash          string
}

type sharedRepoKey struct {
	url    string
	commit string
	auth   string
	folder string
}

type sharedRepoSourceKey struct {
	url  string
	auth string
}

type sharedRepoEntry struct {
	CacheDir
	refs     int
	lastUsed uint64
}

type sharedRepoFlight struct {
	done chan struct{}
	err  error
}

type sharedRepoBranchKey struct {
	url    string
	branch string
	auth   string
}

type sharedRepoBranchHead struct {
	hash      string
	checkedAt time.Time
}

// sharedRepoCache keeps immutable production checkouts across API operations.
// Branch names are never cache keys: callers resolve the current remote SHA
// first, so a branch update creates a new immutable entry. Entries in active
// RepoCache instances are reference counted and cannot be evicted.
type sharedRepoCache struct {
	mu         sync.Mutex
	rootDir    string
	maxEntries int
	clock      uint64
	entries    map[sharedRepoKey]*sharedRepoEntry
	fullRepos  map[sharedRepoSourceKey]sharedRepoKey
	flights    map[sharedRepoKey]*sharedRepoFlight
	branchHead map[sharedRepoBranchKey]sharedRepoBranchHead
}

func newSharedRepoCache(maxEntries int) (*sharedRepoCache, error) {
	rootDir, err := os.MkdirTemp("", "openrun_git_cache_")
	if err != nil {
		return nil, err
	}
	return &sharedRepoCache{
		rootDir:    rootDir,
		maxEntries: maxEntries,
		entries:    make(map[sharedRepoKey]*sharedRepoEntry),
		fullRepos:  make(map[sharedRepoSourceKey]sharedRepoKey),
		flights:    make(map[sharedRepoKey]*sharedRepoFlight),
		branchHead: make(map[sharedRepoBranchKey]sharedRepoBranchHead),
	}, nil
}

func (c *sharedRepoCache) getBranchHead(key sharedRepoBranchKey, maxAge time.Duration) (string, bool) {
	if maxAge <= 0 {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	head, ok := c.branchHead[key]
	if !ok || time.Since(head.checkedAt) > maxAge {
		return "", false
	}
	return head.hash, true
}

func (c *sharedRepoCache) putBranchHead(key sharedRepoBranchKey, hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.branchHead[key]; !exists && len(c.branchHead) >= c.maxEntries*4 {
		var oldestKey sharedRepoBranchKey
		var oldestTime time.Time
		for candidate, head := range c.branchHead {
			if oldestTime.IsZero() || head.checkedAt.Before(oldestTime) {
				oldestKey = candidate
				oldestTime = head.checkedAt
			}
		}
		delete(c.branchHead, oldestKey)
	}
	c.branchHead[key] = sharedRepoBranchHead{hash: hash, checkedAt: time.Now()}
}

// acquireOrStart returns a cached checkout, waits for an in-flight checkout,
// or makes the caller responsible for creating the checkout.
func (c *sharedRepoCache) acquireOrStart(key sharedRepoKey) (CacheDir, *sharedRepoFlight, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		c.clock++
		entry.lastUsed = c.clock
		entry.refs++
		return entry.CacheDir, nil, false
	}
	if flight, ok := c.flights[key]; ok {
		return CacheDir{}, flight, false
	}
	flight := &sharedRepoFlight{done: make(chan struct{})}
	c.flights[key] = flight
	return CacheDir{}, flight, true
}

// acquireFullRepo returns a full-history checkout that can be used as the
// source for a local clone. Holding a reference prevents eviction while the
// clone is in progress.
func (c *sharedRepoCache) acquireFullRepo(key sharedRepoSourceKey) (string, sharedRepoKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	repoKey, ok := c.fullRepos[key]
	if !ok {
		return "", sharedRepoKey{}, false
	}
	entry, ok := c.entries[repoKey]
	if !ok {
		delete(c.fullRepos, key)
		return "", sharedRepoKey{}, false
	}
	c.clock++
	entry.lastUsed = c.clock
	entry.refs++
	return entry.dir, repoKey, true
}

func (c *sharedRepoCache) finish(key sharedRepoKey, dir CacheDir, fullRepo bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	flight := c.flights[key]
	delete(c.flights, key)
	if err == nil {
		c.clock++
		c.entries[key] = &sharedRepoEntry{
			CacheDir: dir,
			refs:     1,
			lastUsed: c.clock,
		}
		if fullRepo {
			c.fullRepos[sharedRepoSourceKey{url: key.url, auth: key.auth}] = key
		}
		c.evictLocked()
	}
	flight.err = err
	close(flight.done)
}

func (c *sharedRepoCache) release(key sharedRepoKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok && entry.refs > 0 {
		entry.refs--
	}
	c.evictLocked()
}

func (c *sharedRepoCache) newCheckoutDir() (string, error) {
	c.mu.Lock()
	rootDir := c.rootDir
	c.mu.Unlock()
	if rootDir == "" {
		return "", fmt.Errorf("git checkout cache is closed")
	}
	return os.MkdirTemp(rootDir, "repo_")
}

func (c *sharedRepoCache) evictLocked() {
	for len(c.entries) > c.maxEntries {
		var oldestKey sharedRepoKey
		var oldest *sharedRepoEntry
		for key, entry := range c.entries {
			if entry.refs != 0 {
				continue
			}
			if oldest == nil || entry.lastUsed < oldest.lastUsed {
				oldestKey = key
				oldest = entry
			}
		}
		if oldest == nil {
			return
		}
		delete(c.entries, oldestKey)
		sourceKey := sharedRepoSourceKey{url: oldestKey.url, auth: oldestKey.auth}
		if c.fullRepos[sourceKey] == oldestKey {
			delete(c.fullRepos, sourceKey)
		}
		os.RemoveAll(oldest.dir) //nolint:errcheck
	}
}

func (c *sharedRepoCache) close() {
	c.mu.Lock()
	rootDir := c.rootDir
	c.rootDir = ""
	c.entries = nil
	c.fullRepos = nil
	c.branchHead = nil
	c.mu.Unlock()
	if rootDir != "" {
		os.RemoveAll(rootDir) //nolint:errcheck
	}
}

type RepoCache struct {
	mu         sync.Mutex
	server     *Server
	rootDir    string
	cache      map[Repo]CacheDir
	shaCache   map[Repo]string // Cache for commit hashes
	shared     *sharedRepoCache
	sharedKeys []sharedRepoKey
}

func NewRepoCache(server *Server) (*RepoCache, error) {
	tmpDir, err := os.MkdirTemp("", "openrun_git_")
	if err != nil {
		return nil, err
	}
	shared, err := server.sharedRepoCache()
	if err != nil {
		os.RemoveAll(tmpDir) //nolint:errcheck
		return nil, err
	}
	return &RepoCache{
		server:   server,
		rootDir:  tmpDir,
		cache:    make(map[Repo]CacheDir),
		shaCache: make(map[Repo]string),
		shared:   shared,
	}, nil
}

func (r *RepoCache) getRepo(key Repo) (CacheDir, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	dir, ok := r.cache[key]
	return dir, ok
}

func (r *RepoCache) putRepo(key Repo, dir CacheDir) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[key] = dir
}

func (r *RepoCache) getSha(key Repo) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sha, ok := r.shaCache[key]
	return sha, ok
}

func (r *RepoCache) putSha(key Repo, sha string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.shaCache[key] = sha
}

func (r *RepoCache) addSharedKey(key sharedRepoKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sharedKeys = append(r.sharedKeys, key)
}

func (s *Server) sharedRepoCache() (*sharedRepoCache, error) {
	maxEntries := s.Config().System.GitCheckoutCacheEntries
	if maxEntries <= 0 {
		return nil, nil
	}
	s.gitCacheMu.Lock()
	defer s.gitCacheMu.Unlock()
	if s.gitCache == nil {
		cache, err := newSharedRepoCache(maxEntries)
		if err != nil {
			return nil, err
		}
		s.gitCache = cache
	}
	return s.gitCache, nil
}

func (s *Server) closeSharedRepoCache() {
	s.gitCacheMu.Lock()
	cache := s.gitCache
	s.gitCache = nil
	s.gitCacheMu.Unlock()
	if cache != nil {
		cache.close()
	}
}

func (r *RepoCache) GetSha(sourceUrl, branch, gitAuth string) (string, error) {
	gitAuth = cmp.Or(gitAuth, r.server.Config().Security.DefaultGitAuth)
	authEntry, err := r.server.loadGitKey(gitAuth)
	if err != nil {
		return "", err
	}

	// Figure on which repo to clone
	repo, _, err := parseGitUrl(sourceUrl, authEntry.usingSSH)
	if err != nil {
		return "", err
	}

	shaKey := Repo{url: repo, branch: branch, auth: gitAuth}
	// Check if this operation has already resolved the branch.
	if sha, ok := r.getSha(shaKey); ok {
		return sha, nil
	}
	branchKey := sharedRepoBranchKey{url: repo, branch: branch, auth: gitAuth}
	checkInterval := time.Duration(r.server.Config().System.GitRemoteCheckIntervalSecs) * time.Second
	if r.shared != nil {
		if sha, ok := r.shared.getBranchHead(branchKey, checkInterval); ok {
			r.putSha(shaKey, sha)
			return sha, nil
		}
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
	r.putSha(shaKey, sha)
	if r.shared != nil {
		r.shared.putBranchHead(branchKey, sha)
	}
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

func (r *RepoCache) CheckoutRepo(sourceUrl, branch, commit, gitAuth string, isDev bool) (_ string, _ string, _ string, _ string, retErr error) {
	gitAuth = cmp.Or(gitAuth, r.server.Config().Security.DefaultGitAuth)
	authEntry, err := r.server.loadGitKey(gitAuth)
	if err != nil {
		return "", "", "", "", err
	}

	// Figure on which repo to clone
	repo, folder, err := parseGitUrl(sourceUrl, authEntry.usingSSH)
	if err != nil {
		return "", "", "", "", err
	}

	cacheFolder := ""
	if commit != "" {
		cacheFolder = folder
	}
	repoKey := Repo{url: repo, branch: branch, commit: commit, auth: gitAuth, folder: cacheFolder, isDev: isDev}
	dir, ok := r.getRepo(repoKey)
	if ok {
		r.server.Debug().Str("repo", repo).Str("branch", branch).
			Str("commit", commit).Str("git_auth", gitAuth).Str("dir", dir.dir).Msg("Using cached git checkout")
		return dir.dir, folder, dir.commitMessage, dir.hash, nil
	}

	var sharedKey sharedRepoKey
	sharedLeader := false
	sharedTargetPath := ""
	sharedResult := CacheDir{}
	sharedFullRepo := false
	if r.shared != nil && !isDev {
		hash := commit
		if commit == "" {
			hash, err = r.GetSha(sourceUrl, branch, gitAuth)
			if err != nil {
				return "", "", "", "", fmt.Errorf("find remote ref %q: %w",
					plumbing.NewBranchReferenceName(branch), err)
			}
		} else if !validGitCommit(commit) {
			return "", "", "", "", fmt.Errorf("error checking out branch %s commit %s: reference not found", branch, commit)
		}
		sharedKey = sharedRepoKey{url: repo, commit: strings.ToLower(hash), auth: gitAuth, folder: cacheFolder}
		for {
			var flight *sharedRepoFlight
			var leader bool
			if dir, flight, leader = r.shared.acquireOrStart(sharedKey); dir.dir != "" {
				r.putRepo(repoKey, dir)
				r.addSharedKey(sharedKey)
				r.server.Debug().Str("repo", repo).Str("branch", branch).Str("commit", commit).
					Str("git_auth", gitAuth).Str("dir", dir.dir).Msg("Using shared git checkout")
				return dir.dir, folder, dir.commitMessage, dir.hash, nil
			}
			if leader {
				sharedLeader = true
				break
			}
			<-flight.done
			if flight.err != nil {
				return "", "", "", "", flight.err
			}
		}
		defer func() {
			if retErr != nil && sharedTargetPath != "" {
				os.RemoveAll(sharedTargetPath) //nolint:errcheck
			}
			r.shared.finish(sharedKey, sharedResult, sharedFullRepo, retErr)
		}()
	}

	cloneOptions := git.CloneOptions{
		URL:  repo,
		Tags: git.NoTags, // Don't fetch tags, to speed up checkout
	}

	if commit == "" {
		// No commit id specified, checkout specified branch
		cloneOptions.ReferenceName = plumbing.NewBranchReferenceName(branch)
		cloneOptions.SingleBranch = true
		if !isDev {
			cloneOptions.Depth = 1
		}
	}

	var auth transport.AuthMethod
	if gitAuth != "" {
		r.server.Info().Msgf("Using git auth %s", gitAuth)
		auth, err = r.createAuthMethod(gitAuth)
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
	} else if sharedLeader {
		targetPath, err = r.shared.newCheckoutDir()
		if err != nil {
			return "", "", "", "", err
		}
		sharedTargetPath = targetPath
	} else {
		targetPath, err = os.MkdirTemp(r.rootDir, "repo_")
		if err != nil {
			return "", "", "", "", err
		}
	}

	cloneAndCheckout := func(cloneURL string, cloneAuth transport.AuthMethod) (*git.Repository, error) {
		options := cloneOptions
		options.URL = cloneURL
		options.Auth = cloneAuth
		r.server.Info().Msgf("Cloning git repo %s to %s", repo, targetPath)
		r.server.Trace().Str("source_url", sourceUrl).Str("clone_url", cloneURL).Str("repo", repo).Str("folder", folder).
			Str("branch", branch).Str("commit", commit).Str("git_auth", gitAuth).Bool("is_dev", isDev).
			Bool("single_branch", options.SingleBranch).Int("depth", options.Depth).
			Str("target_path", targetPath).Msg("Starting git clone for app source")
		gitRepo, cloneErr := git.PlainClone(targetPath, false, &options)
		if cloneErr != nil {
			return nil, fmt.Errorf("error checking out branch %s: %w", branch, cloneErr)
		}
		if commit == "" {
			r.server.Trace().Str("repo", repo).Str("branch", branch).Str("target_path", targetPath).
				Msg("Skipping explicit branch checkout after clone")
			return gitRepo, nil
		}

		// PlainClone checks out the requested branch when commit is empty. A second
		// checkout can fail on Windows if go-git sees the fresh worktree as dirty.
		w, worktreeErr := gitRepo.Worktree()
		if worktreeErr != nil {
			return nil, worktreeErr
		}
		r.server.Info().Msgf("Checking out commit %s", commit)
		if checkoutErr := w.Checkout(&git.CheckoutOptions{Hash: plumbing.NewHash(commit)}); checkoutErr != nil {
			if status, statusErr := w.Status(); statusErr == nil && !status.IsClean() {
				r.server.Debug().Str("repo", repo).Str("branch", branch).Str("commit", commit).Str("target_path", targetPath).
					Interface("worktree_status", status).Msg("Git checkout failed with dirty worktree")
			} else if statusErr != nil {
				r.server.Debug().Err(statusErr).Str("repo", repo).Str("branch", branch).Str("commit", commit).
					Str("target_path", targetPath).Msg("Git checkout failed and worktree status could not be read")
			}
			return nil, fmt.Errorf("error checking out branch %s commit %s: %w", branch, commit, checkoutErr)
		}
		return gitRepo, nil
	}

	cloneURL := repo
	cloneAuth := auth
	var fullRepoKey sharedRepoKey
	usingFullRepo := false
	if sharedLeader && commit != "" {
		sourceKey := sharedRepoSourceKey{url: repo, auth: gitAuth}
		if fullRepoPath, key, ok := r.shared.acquireFullRepo(sourceKey); ok {
			cloneURL = fullRepoPath
			cloneAuth = nil
			fullRepoKey = key
			usingFullRepo = true
			defer r.shared.release(fullRepoKey)
			if folder != "" {
				message, hash, materializeErr := materializeGitCommit(fullRepoPath, targetPath, commit, folder)
				if materializeErr == nil {
					cacheDir := CacheDir{dir: targetPath, commitMessage: message, hash: hash}
					r.putRepo(repoKey, cacheDir)
					sharedResult = cacheDir
					r.addSharedKey(sharedKey)
					return targetPath, folder, message, hash, nil
				}
				r.server.Debug().Err(materializeErr).Str("repo", repo).Str("commit", commit).Str("folder", folder).
					Msg("Unable to materialize cached git commit, falling back to clone")
				os.RemoveAll(targetPath) //nolint:errcheck
				if mkdirErr := os.MkdirAll(targetPath, 0744); mkdirErr != nil {
					return "", "", "", "", mkdirErr
				}
			}
		}
	}

	gitRepo, err := cloneAndCheckout(cloneURL, cloneAuth)
	if err != nil && usingFullRepo {
		// The cached full-history repo may predate an explicitly requested
		// commit. Retry against the authoritative remote before failing.
		os.RemoveAll(targetPath) //nolint:errcheck
		if mkdirErr := os.MkdirAll(targetPath, 0744); mkdirErr != nil {
			return "", "", "", "", mkdirErr
		}
		gitRepo, err = cloneAndCheckout(repo, auth)
	}
	if err != nil {
		return "", "", "", "", err
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
	cacheDir := CacheDir{
		dir:           targetPath,
		commitMessage: newCommit.Message,
		hash:          newCommit.Hash.String(),
	}
	r.putRepo(repoKey, cacheDir)
	if sharedLeader {
		sharedResult = cacheDir
		sharedFullRepo = commit != ""
		r.addSharedKey(sharedKey)
	}

	return targetPath, folder, newCommit.Message, newCommit.Hash.String(), nil
}

func validGitCommit(commit string) bool {
	const gitCommitHexLength = 40
	if len(commit) != gitCommitHexLength {
		return false
	}
	_, err := hex.DecodeString(commit)
	return err == nil
}

// materializeGitCommit writes one folder from a commit already available in a
// full-history checkout. It avoids copying the source checkout's complete git
// object database merely to read a small app subdirectory at another commit.
func materializeGitCommit(sourceDir, targetDir, commit, folder string) (string, string, error) {
	repo, err := git.PlainOpen(sourceDir)
	if err != nil {
		return "", "", err
	}
	commitObject, err := repo.CommitObject(plumbing.NewHash(commit))
	if err != nil {
		return "", "", err
	}
	tree, err := commitObject.Tree()
	if err != nil {
		return "", "", err
	}
	prefix := strings.Trim(folder, "/")
	err = tree.Files().ForEach(func(file *object.File) error {
		name := strings.TrimPrefix(filepath.ToSlash(file.Name), "/")
		if prefix != "" && name != prefix && !strings.HasPrefix(name, prefix+"/") {
			return nil
		}
		targetPath := filepath.Join(targetDir, filepath.FromSlash(name))
		relativePath, err := filepath.Rel(targetDir, targetPath)
		if err != nil || relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
			return fmt.Errorf("invalid path %q in git tree", file.Name)
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0744); err != nil {
			return err
		}
		if file.Mode == filemode.Symlink {
			linkTarget, err := file.Contents()
			if err != nil {
				return err
			}
			return os.Symlink(linkTarget, targetPath)
		}
		mode, err := file.Mode.ToOSFileMode()
		if err != nil {
			return err
		}
		reader, err := file.Reader()
		if err != nil {
			return err
		}
		output, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode.Perm())
		if err != nil {
			reader.Close() //nolint:errcheck
			return err
		}
		_, copyErr := io.Copy(output, reader)
		closeErr := output.Close()
		readerErr := reader.Close()
		return cmp.Or(copyErr, closeErr, readerErr)
	})
	if err != nil {
		return "", "", err
	}
	return commitObject.Message, commitObject.Hash.String(), nil
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
	r.mu.Lock()
	sharedKeys := r.sharedKeys
	r.sharedKeys = nil
	r.mu.Unlock()
	for _, key := range sharedKeys {
		r.shared.release(key)
	}
	if r.rootDir != "" {
		os.RemoveAll(r.rootDir) //nolint:errcheck
		r.rootDir = ""
	}
}
