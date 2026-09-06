// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

// The pre-transaction pass of the app deploy operations (create, reload, apply,
// sync, promote). The metadata database transaction of a deploy is a single
// writer on sqlite, so the work that does not need the database runs before
// the transaction opens: the git checkout, hashing and compressing the source
// files, loading the app definition, building the image and running the
// before_deploy gate jobs. The transaction then holds only the database
// writes, plus the container reload of the updated instances. The pass hands
// its results to the transaction through appPrep values.

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"

	apppkg "github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/metadata"
	"github.com/openrundev/openrun/internal/types"
)

// appPrep is the pre-pass result for one app, consumed by the transaction
type appPrep struct {
	// files is the app's source, hashed and compressed, for the transaction to
	// insert. loadDir and gitCommit identify the source it was read from; the
	// transaction uses the files only when its own checkout resolves to the
	// same source (see preparedFiles)
	files     *metadata.PreparedFiles
	loadDir   string
	gitCommit string

	// The fields below are set by the create pre-pass only

	// appId is the app id the pre-pass ran with; the transaction creates the
	// app under the same id, so the gate job runs recorded by the pre-pass
	// belong to the created app. consumed is set by CreateAppTx when it
	// creates the app from this prep
	appId    types.AppId
	consumed bool
	// cleanupIds are the instances the create brings into being (the prod and
	// stage apps, or the dev app), whose runtime resources - gate job runs and
	// containers, the built image, containers started by verify, run dirs -
	// are removed by finish unless the create committed, since they would
	// belong to an app that never existed
	cleanupIds []types.AppId
	dryRun     bool
	// devPrepared is set when the pre-pass built and started the dev app's
	// container (a dev reload rebuilds and recreates, it has no reuse path),
	// so the transaction's reload skips the container
	devPrepared bool
	// gatesHandled is set when the pre-pass covered the definition load and
	// before_deploy gate step, so the transaction skips it. It stays unset
	// when the gates need bindings that only exist inside the transaction
	gatesHandled bool
	// loaded is set when the app definition loaded in the pre-pass;
	// definitionJobs are the jobs it declared, persisted by the transaction
	loaded         bool
	definitionJobs []string
}

// newCreatePrep returns the create pre-pass result for an app id, before any
// source or gate work: it owns the cleanup of the instances the create would
// bring into being
func newCreatePrep(appId types.AppId, isDev, dryRun bool) *appPrep {
	prep := &appPrep{appId: appId, dryRun: dryRun, cleanupIds: []types.AppId{appId}}
	if !isDev {
		prep.cleanupIds = append(prep.cleanupIds, stageAppId(appId))
	}
	return prep
}

// preparedFiles returns the prepared source files when they were read from
// the source the transaction resolved (loadDir, and the git commit for a git
// source), nil otherwise: the transaction then loads the files itself
func (p *appPrep) preparedFiles(loadDir, gitCommit string) *metadata.PreparedFiles {
	if p == nil || p.files == nil || p.loadDir != loadDir || p.gitCommit != gitCommit {
		return nil
	}
	return p.files
}

// finish releases the pre-pass resources. committed reports whether the
// operation's database transaction committed (not whether the operation
// succeeded: a post-commit failure keeps the created app, and its gate
// history with it). Unless a create was consumed by the transaction and the
// transaction committed, the instances it would have created never existed:
// their gate run records and containers, image, verify containers and run
// dirs are removed as for a deleted app. Nothing was created on a dry run
func (p *appPrep) finish(ctx context.Context, s *Server, committed bool) {
	if p == nil || len(p.cleanupIds) == 0 || p.dryRun || (committed && p.consumed) {
		return
	}
	cleanupCtx := context.WithoutCancel(ctx)
	if err := s.removeAppRuntimeResources(cleanupCtx, p.cleanupIds); err != nil {
		s.Warn().Err(err).Msgf("error removing the resources of the uncommitted create of app %s", p.appId)
	}
	p.cleanupIds = nil
}

// deployPreps is the pre-pass result of a multi app operation, by app path
type deployPreps map[types.AppPathDomain]*appPrep

func (d deployPreps) finish(ctx context.Context, s *Server, committed bool) {
	for _, prep := range d {
		prep.finish(ctx, s, committed)
	}
}

type deployPrepsCtxKey struct{}

// withDeployPreps attaches pre-pass results to the context, for an Apply that
// runs on a transaction opened by the caller (sync): the caller runs the
// pre-pass before opening its transaction and owns the results
func withDeployPreps(ctx context.Context, preps deployPreps) context.Context {
	if len(preps) == 0 {
		return ctx
	}
	return context.WithValue(ctx, deployPrepsCtxKey{}, preps)
}

func deployPrepsFromContext(ctx context.Context) deployPreps {
	preps, _ := ctx.Value(deployPrepsCtxKey{}).(deployPreps)
	return preps
}

// gatesNeedImage reports whether a before_deploy gate runs from the app image
func gatesNeedImage(gates []types.JobSpec) bool {
	for _, spec := range gates {
		if !spec.IsRun() {
			return true
		}
	}
	return false
}

// buildGateImage builds the app image when a before_deploy gate runs from it,
// or when force is set (verify with the image pre-build step). plan is the
// app's build plan, prepared here when nil; it is discarded when no build is
// needed. The build reads only from the plan's temp source dir, never the
// database
func (s *Server) buildGateImage(ctx context.Context, application *apppkg.App, plan *apppkg.BuildPlan, gates []types.JobSpec, force bool) error {
	if plan == nil {
		var err error
		if plan, err = application.PrepareContainerBuild(ctx); err != nil {
			return err
		}
	}
	if force || gatesNeedImage(gates) {
		return application.ExecuteContainerBuild(ctx, plan)
	}
	application.DiscardContainerBuild(plan)
	return nil
}

// prepareAppCode is the pre-transaction part of a code load: the up-to-date
// checks of loadAppCode, the source checkout into the repo cache and the
// hashing and compression of the files. appEntry is updated with the git info
// and the version the load will assign, as the transaction does. Returns a
// nil prep when there is nothing to reload
func (s *Server) prepareAppCode(ctx context.Context, appEntry *types.AppEntry, branch, commit, gitAuth string,
	repoCache *RepoCache, forceReload bool) (*appPrep, error) {
	upToDate, err := s.appCodeUpToDate(ctx, appEntry, branch, commit, gitAuth, repoCache, forceReload)
	if err != nil || upToDate {
		return nil, err
	}
	loadDir, err := s.checkoutAppSource(ctx, appEntry, branch, commit, gitAuth, repoCache)
	if err != nil {
		return nil, err
	}
	if err := s.assignNextVersion(ctx, types.Transaction{}, appEntry); err != nil {
		return nil, err
	}
	fileStore, err := metadata.NewFileStore(appEntry.Id, appEntry.Metadata.VersionMetadata.Version, s.db, types.Transaction{})
	if err != nil {
		return nil, err
	}
	files, err := fileStore.PrepareAppFiles(ctx, loadDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read source %s: %w", appEntry.SourceUrl, err)
	}
	return &appPrep{files: files, loadDir: loadDir, gitCommit: appEntry.Metadata.VersionMetadata.GitCommit}, nil
}

// setupPrepApp builds the pre-pass app object of a prod instance over the
// directory its code was read from, instead of the database, so the pre-pass
// needs no database writes. cleanup releases the temp dir stood in for an
// app with no source. bindings are the instance's bindings, as resolved by the
// caller
func (s *Server) setupPrepApp(appEntry *types.AppEntry, prep *appPrep, bindings []*types.Binding) (_ *apppkg.App, cleanup func(), _ error) {
	cleanup = func() {}
	appDir := prep.loadDir
	if s.staticServeFromDisk(appEntry) {
		appDir = appEntry.SourceUrl
	} else if appDir == types.NO_SOURCE {
		tempDir, err := os.MkdirTemp("", "openrun-prepare-")
		if err != nil {
			return nil, cleanup, err
		}
		cleanup = func() { os.RemoveAll(tempDir) } //nolint:errcheck
		appDir = tempDir
	}
	application, err := s.setupAppFromDir(appEntry, appDir, bindings)
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	return application, cleanup, nil
}

// prepareAppImage loads one app's new code for the pre-pass: the source is
// checked out and compressed (prepareAppCode), the app object is built over
// the checkout, audited and loaded without its container, and its build plan
// prepared (the build inputs extracted to a temp dir). Returns a nil app when
// there is nothing to reload. The prep carries the compressed files for the
// transaction's load. cleanup releases the app object's source dir stand-in
// (see setupPrepApp): the caller runs it once done with the app
func (s *Server) prepareAppImage(ctx context.Context, appPathDomain types.AppPathDomain, approve bool,
	branch, commit, gitAuth string, repoCache *RepoCache, forceReload bool) (_ *apppkg.App, _ *apppkg.BuildPlan, _ *appPrep, cleanup func(), _ error) {
	appEntry, err := s.db.GetAppEntry(ctx, appPathDomain)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if !appEntry.IsDev {
		if appEntry, err = s.getStageAppNoTx(ctx, appEntry); err != nil {
			return nil, nil, nil, nil, err
		}
	}

	prep, err := s.prepareAppCode(ctx, appEntry, branch, commit, gitAuth, repoCache, forceReload)
	if err != nil || prep == nil {
		return nil, nil, nil, nil, err
	}

	bindings, err := s.getAppBindings(ctx, types.Transaction{}, appEntry)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	application, cleanup, err := s.setupPrepApp(appEntry, prep, bindings)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("error setting up app %s: %w", appEntry, err)
	}
	fail := func(err error) (*apppkg.App, *apppkg.BuildPlan, *appPrep, func(), error) {
		application.Close() //nolint:errcheck // throwaway app object, stop its background tickers
		cleanup()
		return nil, nil, nil, nil, err
	}

	// Mirror the audit/approval sequence of ReloadApp so the app loads with the
	// same (in-memory) approvals it will have in the main pass, and so apps
	// needing approval fail here, before any state has been mutated
	auditResult, err := application.Audit()
	if err != nil {
		return fail(fmt.Errorf("error auditing app %s: %w", appEntry, err))
	}
	if auditResult.NeedsApproval && !approve {
		return fail(fmt.Errorf("app %s needs approval", appEntry))
	}
	if approve {
		s.approveAuditResult(application, auditResult)
	}

	if _, err := application.Reload(ctx, true, true, types.DryRunFalse, apppkg.ReloadOptions{SkipContainer: true}); err != nil {
		return fail(fmt.Errorf("error reloading app %s: %w", appEntry, err))
	}

	plan, err := application.PrepareContainerBuild(ctx)
	if err != nil {
		return fail(err)
	}
	return application, plan, prep, cleanup, nil
}

// prepareDeploy is the pre-transaction pass of a code deploy (reload, apply
// with reload, sync) for one existing app: the new source is checked out and
// compressed, the image is built, the stage before_deploy jobs run from that
// image against the stage instance (with promote, the prod gates run right
// after, against the prod instance), and the new version's containers are
// started and health checked (see prepareInstance). Nothing has been
// committed when this returns; the containers are registered on the
// operation's deploy scope (which must be in ctx) for rollback. The returned
// prep (nil when there is nothing to reload) carries the compressed files
// for the transaction's load
func (s *Server) prepareDeploy(ctx context.Context, appPathDomain types.AppPathDomain, approve, promote, verify bool,
	branch, commit, gitAuth string, repoCache *RepoCache, forceReload bool, reason string) (*appPrep, error) {
	current, err := s.db.GetAppEntry(ctx, appPathDomain)
	if err != nil {
		return nil, err
	}
	if current.IsDev {
		return s.prepareDevDeploy(ctx, current, approve, branch, commit, gitAuth, repoCache, forceReload)
	}
	stageEntry, err := s.getStageAppNoTx(ctx, current)
	if err != nil {
		return nil, err
	}
	previousVersion := stageEntry.Metadata.VersionMetadata.Version

	application, plan, prep, cleanup, err := s.prepareAppImage(ctx, appPathDomain, approve, branch, commit, gitAuth, repoCache, forceReload)
	if err != nil || application == nil {
		return nil, err
	}
	defer cleanup()
	defer application.Close() //nolint:errcheck

	gates, err := application.BeforeDeployJobs()
	if err != nil {
		return nil, err
	}
	// The image is always built here, so the transaction never builds
	if err := s.buildGateImage(ctx, application, plan, gates, true); err != nil {
		return nil, err
	}
	if len(gates) > 0 {
		// The version the reload allocated for the new code (the highest
		// version plus one, not necessarily the current version plus one)
		newVersion := application.Metadata.VersionMetadata.Version
		if newVersion <= previousVersion {
			newVersion = previousVersion + 1
		}
		if err := s.runDeployGates(ctx, types.Transaction{}, application, stageEntry, reason, newVersion, previousVersion); err != nil {
			return nil, err
		}
		if promote {
			if err := s.runDeployGates(ctx, types.Transaction{}, application, current, "promote", newVersion, current.Metadata.VersionMetadata.Version); err != nil {
				return nil, err
			}
		}
	}

	// Start and health check the new version's containers, as the
	// transaction's reload will: it then finds them running and reuses them
	if err := s.prepareInstance(ctx, application, verify); err != nil {
		return nil, err
	}
	if promote {
		if err := s.preparePromotedInstance(ctx, current, application.AppEntry, prep, verify); err != nil {
			return nil, err
		}
	}
	return prep, nil
}

// prepareDevDeploy is the pre-transaction pass of a dev app's code reload:
// the source files are compressed for the transaction's version insert, and
// the dev image is built and the dev container started and health checked
// on a throwaway app object over the source dir, as the transaction's reload
// would (a dev reload always rebuilds, so the transaction's reload skips the
// container instead of reusing it, see appPrep.devPrepared). Dev apps run no
// gates and are not registered for rollback: their container serves the
// source dir, which is already changed. Returns nil when there is nothing to
// reload
func (s *Server) prepareDevDeploy(ctx context.Context, entry *types.AppEntry, approve bool,
	branch, commit, gitAuth string, repoCache *RepoCache, forceReload bool) (*appPrep, error) {
	prep, err := s.prepareAppCode(ctx, entry, branch, commit, gitAuth, repoCache, forceReload)
	if err != nil || prep == nil {
		return nil, err
	}
	application, err := s.setupApp(ctx, entry, types.Transaction{})
	if err != nil {
		return nil, fmt.Errorf("error setting up app %s: %w", entry, err)
	}
	defer application.Close() //nolint:errcheck
	if err := s.prepareDevInstance(ctx, application, approve); err != nil {
		return nil, err
	}
	prep.devPrepared = true
	return prep, nil
}

// prepareDevInstance audits the dev app object (failing when it needs an
// approval the caller does not give, before anything is mutated) and reloads
// it with its container: the dev image build, container start and health
// check
func (s *Server) prepareDevInstance(ctx context.Context, application *apppkg.App, approve bool) error {
	auditResult, err := application.Audit()
	if err != nil {
		return fmt.Errorf("error auditing app %s: %w", application.AppEntry, err)
	}
	if auditResult.NeedsApproval && !approve {
		return fmt.Errorf("app %s needs approval", application.AppEntry)
	}
	if approve {
		s.approveAuditResult(application, auditResult)
	}
	return s.reloadInstance(ctx, application, false, false)
}

// preparePromotedInstance starts and health checks the prod instance's
// container for the stage code about to be promoted to it, on a pre-pass
// app object built as promoteApp will build the prod entry: the prod entry
// with the (loaded) stage metadata and the stage version
func (s *Server) preparePromotedInstance(ctx context.Context, prodEntry, stageEntry *types.AppEntry, prep *appPrep, verify bool) error {
	entry := *prodEntry
	entry.Metadata = stageEntry.Metadata
	entry.Metadata.VersionMetadata.PreviousVersion = prodEntry.Metadata.VersionMetadata.Version
	bindings, err := s.getAppBindings(ctx, types.Transaction{}, &entry)
	if err != nil {
		return err
	}
	application, cleanup, err := s.setupPrepApp(&entry, prep, bindings)
	if err != nil {
		return fmt.Errorf("error setting up prod app %s: %w", &entry, err)
	}
	defer cleanup()
	defer application.Close() //nolint:errcheck
	return s.prepareInstance(ctx, application, verify)
}

// prepareDeploys runs prepareDeploy for each app, in app path order
func (s *Server) prepareDeploys(ctx context.Context, apps []types.AppPathDomain, approve, promote, verify bool,
	branch, commit, gitAuth string, repoCache *RepoCache, forceReload bool, reason string) (deployPreps, error) {
	sorted := append([]types.AppPathDomain{}, apps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].String() < sorted[j].String() })
	preps := deployPreps{}
	for _, appPathDomain := range sorted {
		prep, err := s.prepareDeploy(ctx, appPathDomain, approve, promote, verify, branch, commit, gitAuth, repoCache, forceReload, reason)
		if err != nil {
			return nil, err
		}
		if prep != nil {
			preps[appPathDomain] = prep
		}
	}
	return preps, nil
}

// preparePromote runs the prod before_deploy jobs of the stage code against
// the prod instance, before the promote transaction opens. Returns the prod
// version the gates ran against, for the transaction's change check
func (s *Server) preparePromote(ctx context.Context, appPathDomain types.AppPathDomain) (int, error) {
	prodEntry, err := s.db.GetAppEntry(ctx, appPathDomain)
	if err != nil {
		return 0, err
	}
	if !strings.HasPrefix(string(prodEntry.Id), types.ID_PREFIX_APP_PROD) {
		return prodEntry.Metadata.VersionMetadata.Version, nil
	}
	stageEntry, err := s.getStageAppNoTx(ctx, prodEntry)
	if err != nil {
		return 0, err
	}
	stageJobs, _, err := types.EffectiveJobs(&stageEntry.Metadata)
	if err != nil {
		return 0, err
	}
	hasGate := false
	for _, spec := range stageJobs {
		if spec.IsEnabled() && spec.TriggerType() == types.JobTriggerBeforeDeploy {
			hasGate = true
		}
	}
	if !hasGate {
		return prodEntry.Metadata.VersionMetadata.Version, nil
	}
	application, closeApp, err := s.loadJobApp(ctx, types.Transaction{}, stageEntry)
	if err != nil {
		return 0, err
	}
	defer closeApp()
	err = s.runDeployGates(ctx, types.Transaction{}, application, prodEntry, "promote",
		stageEntry.Metadata.VersionMetadata.Version, prodEntry.Metadata.VersionMetadata.Version)
	return prodEntry.Metadata.VersionMetadata.Version, err
}

// prepareCreate is the pre-transaction pass of an app create, the create
// counterpart of prepareDeploy: the git source is checked out into the repo
// cache and the source files are hashed and compressed; then the app
// definition is loaded from the checkout, the image is built when the
// before_deploy gates need it, and the gates run against the stage instance.
// A gate failure fails the create; nothing has been written when this returns.
//
// The result is consumed by CreateAppTx, which creates the app under the same
// id and skips the steps done here. The transaction still validates the
// request and audits the loaded code itself. The prep always carries the app
// id, so the runtime resources of a create that does not commit can be
// removed (see appPrep.finish); it carries nothing else for a dev app (its
// files are not loaded into the database and it has no create gates) and when
// the source cannot be checked out or read (the transaction reports the error
// with its guidance). The gates run inside the transaction as before when
// they need bindings that are created there (the app's auto bindings, or
// bindings declared by the same apply). With verify, the stage and prod
// containers are started and health checked here as well, as the apply's
// verify of the created app will (which then reuses them). On an error the
// prep is returned along with it, still owning the cleanup of the resources
// the pass created (see appPrep.finish, to be run after the deploy scope's
// rollback); the deploy scope must be in ctx
func (s *Server) prepareCreate(ctx context.Context, appPath string, approve, dryRun, verify bool,
	appRequest *types.CreateAppRequest, repoCache *RepoCache) (*appPrep, error) {
	appId, err := newAppID(appRequest.IsDev)
	if err != nil {
		return nil, err
	}
	prep := newCreatePrep(appId, appRequest.IsDev, dryRun)
	appEntry, err := s.newCreateAppEntry(ctx, appPath, appRequest)
	if err != nil {
		return nil, err
	}
	if err := s.validateCreateSource(appEntry); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	appEntry.Id = appId
	if appEntry.Metadata.SpecFiles, err = s.specFilesFor(appEntry.Metadata.Spec); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	if appRequest.IsDev {
		// A dev app serves from its source dir, no files are loaded and no
		// gates run. A verified create starts its container here, as the
		// verify in the transaction would (which then skips the container).
		// A git source is checked out first: the entry then points at the
		// local checkout, as the transaction's load makes it
		if !verify || dryRun {
			return prep, nil
		}
		if _, err := s.checkoutAppSource(ctx, appEntry, appRequest.GitBranch, appRequest.GitCommit, appRequest.GitAuthName, repoCache); err != nil {
			s.Debug().Err(err).Msgf("create pre-pass: error checking out %s", appEntry.SourceUrl)
			return prep, nil
		}
		return s.prepareDevCreate(ctx, appEntry, approve, appRequest.Bindings, prep)
	}
	// The create loads the code into, and gates, the stage instance
	stageEntry, err := s.prepareStageAppEntry(ctx, appEntry, appRequest)
	if err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}

	// Locate the source, checking out a git source into the repo cache (the
	// transaction's load then hits the cache), and compress its files
	loadDir, err := s.checkoutAppSource(ctx, stageEntry, appRequest.GitBranch, appRequest.GitCommit, appRequest.GitAuthName, repoCache)
	if err != nil {
		s.Debug().Err(err).Msgf("create pre-pass: error checking out %s", stageEntry.SourceUrl)
		return prep, nil
	}
	stageEntry.Metadata.VersionMetadata.Version = 1 // the version the create assigns to a new app's code
	fileStore, err := metadata.NewFileStore(stageEntry.Id, stageEntry.Metadata.VersionMetadata.Version, s.db, types.Transaction{})
	if err != nil {
		return prep, err
	}
	files, err := fileStore.PrepareAppFiles(ctx, loadDir)
	if err != nil {
		s.Debug().Err(err).Msgf("create pre-pass: error reading source %s", stageEntry.SourceUrl)
		return prep, nil
	}
	prep.files, prep.loadDir, prep.gitCommit = files, loadDir, stageEntry.Metadata.VersionMetadata.GitCommit

	bindings, complete, err := s.prepareCreateBindings(ctx, appEntry.Id, appRequest.Bindings)
	if err != nil {
		return prep, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	for _, binding := range bindings {
		stageEntry.Metadata.Bindings = append(stageEntry.Metadata.Bindings, binding.Path)
	}

	application, cleanup, err := s.setupPrepApp(stageEntry, prep, bindings)
	if err != nil {
		return prep, err
	}
	defer cleanup()
	defer application.Close() //nolint:errcheck

	// Mirror the create transaction's audit and approval, so the definition
	// loads with the approvals it will have (the transaction audits again
	// and persists the result)
	auditResult, err := application.Audit()
	if err != nil {
		return prep, types.CreateRequestError(fmt.Sprintf("app %s audit failed: %s", stageEntry.Id, err), http.StatusBadRequest)
	}
	if auditResult.NeedsApproval && !approve {
		// The transaction skips the definition load and the gates as well
		return prep, nil
	}
	application.Metadata.Loads = auditResult.NewLoads
	application.Metadata.Permissions = auditResult.NewPermissions

	_, reloadErr := application.Reload(ctx, true, true, types.DryRun(dryRun), apppkg.ReloadOptions{SkipContainer: true})
	var gates []types.JobSpec
	if reloadErr == nil {
		if gates, err = application.BeforeDeployJobs(); err != nil {
			return prep, types.CreateRequestError(err.Error(), http.StatusBadRequest)
		}
	}
	if !complete && (reloadErr != nil || len(gates) > 0 || verify) {
		// Some bindings are created inside the transaction; a definition that
		// may need them, gates that do, and the verify's containers run there
		s.Debug().Msgf("create pre-pass: app %s has bindings created by the transaction, its before_deploy gates run there", appPath)
		return prep, nil
	}
	prep.gatesHandled = true
	if reloadErr != nil {
		// Same lazy semantics as the transaction: the error surfaces on the
		// first request, the jobs are persisted by the next reload
		s.Warn().Err(reloadErr).Msgf("app %s did not load at create; its jobs and before_deploy gates apply on the next reload", stageEntry)
		return prep, nil
	}
	prep.loaded = true
	prep.definitionJobs = application.Metadata.DefinitionJobs
	if dryRun {
		// Gates and container starts have side effects, never on a dry run
		return prep, nil
	}

	if len(gates) > 0 {
		if err := s.buildGateImage(ctx, application, nil, gates, false); err != nil {
			return prep, types.CreateRequestError(err.Error(), http.StatusBadRequest)
		}
		// The run records are written outside any transaction and the job
		// containers are created under the stage app id; finish removes them
		// unless the create commits
		if err := s.runDeployGates(ctx, types.Transaction{}, application, stageEntry, "create",
			stageEntry.Metadata.VersionMetadata.Version, 0); err != nil {
			return prep, types.CreateRequestError(err.Error(), http.StatusBadRequest)
		}
	}
	if !verify {
		return prep, nil
	}
	// Verified create (apply --verify): the stage and prod containers are
	// started and health checked as verifyCreatedApp will, which then reuses
	// them. The prod instance gets the stage code and metadata, as the
	// create's promote gives it
	if err := s.prepareInstance(ctx, application, true); err != nil {
		return prep, err
	}
	prodEntry := *appEntry
	prodEntry.Metadata = stageEntry.Metadata
	prodEntry.Metadata.VersionMetadata.PreviousVersion = 0
	prodApp, prodCleanup, err := s.setupPrepApp(&prodEntry, prep, bindings)
	if err != nil {
		return prep, fmt.Errorf("error setting up prod app %s: %w", &prodEntry, err)
	}
	defer prodCleanup()
	defer prodApp.Close() //nolint:errcheck
	if err := s.prepareInstance(ctx, prodApp, true); err != nil {
		return prep, err
	}
	return prep, nil
}

// prepareDevCreate is the verified create pre-pass of a dev app: the dev
// image is built and the dev container started and health checked on a
// throwaway app object, as verifyCreatedApp would in the transaction. Left
// to the transaction when a binding is created there
func (s *Server) prepareDevCreate(ctx context.Context, appEntry *types.AppEntry, approve bool, bindingRefs []string, prep *appPrep) (*appPrep, error) {
	bindings, complete, err := s.prepareCreateBindings(ctx, appEntry.Id, bindingRefs)
	if err != nil {
		return prep, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	if !complete {
		return prep, nil
	}
	for _, binding := range bindings {
		appEntry.Metadata.Bindings = append(appEntry.Metadata.Bindings, binding.Path)
	}
	application, err := s.setupApp(ctx, appEntry, types.Transaction{})
	if err != nil {
		return prep, fmt.Errorf("error setting up app %s: %w", appEntry, err)
	}
	defer application.Close() //nolint:errcheck
	if err := s.prepareDevInstance(ctx, application, approve); err != nil {
		return prep, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	prep.devPrepared = true
	return prep, nil
}

// prepareCreateBindings returns the app's existing bindings (references by
// binding path) with their accounts, for the create pre-pass app object, with
// the same checks resolveAppBindings applies to a newly attached binding. Its
// second result reports whether every reference resolved: a service source
// reference is an auto binding created inside the transaction, and a binding
// path may be declared by the same apply, also created inside the transaction;
// neither can be provided by the pre-pass
func (s *Server) prepareCreateBindings(ctx context.Context, appID types.AppId, bindingRefs []string) ([]*types.Binding, bool, error) {
	tx, err := s.db.BeginTransaction(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback() //nolint:errcheck

	complete := true
	seen := make(map[string]bool, len(bindingRefs))
	bindings := make([]*types.Binding, 0, len(bindingRefs))
	for _, bindingRef := range bindingRefs {
		if bindingRef == "" {
			return nil, false, fmt.Errorf("binding path cannot be empty")
		}
		if !strings.HasPrefix(bindingRef, "/") {
			complete = false
			continue
		}
		if seen[bindingRef] {
			continue
		}
		seen[bindingRef] = true
		if strings.HasPrefix(bindingRef, autoBindingPathPrefix+"/") &&
			!strings.HasPrefix(bindingRef, autoBindingPathForAppID(appID, "")) {
			return nil, false, fmt.Errorf("binding %s is an auto binding owned by another app and cannot be attached", bindingRef)
		}
		binding, err := s.GetBindingWithAccount(ctx, tx, bindingRef)
		if err != nil {
			if strings.HasPrefix(err.Error(), "binding not found with path: ") {
				// Not created yet: an apply creates the bindings it declares
				// inside its transaction, before the apps. The transaction
				// reports a binding that is really missing
				complete = false
				continue
			}
			return nil, false, err
		}
		// Attaching a binding hands its credentials to the app (here, to its
		// gate jobs), so the use permission is checked before any gate runs
		if err := s.enforceBindingPerm(ctx, types.PermissionBindingUse, binding.Path, binding.CreatedBy); err != nil {
			return nil, false, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, complete, nil
}

// checkoutBranch resolves the branch a git source is checked out from
func checkoutBranch(branch string, appEntry *types.AppEntry) string {
	return cmp.Or(branch, appEntry.Metadata.VersionMetadata.GitBranch, "main")
}
