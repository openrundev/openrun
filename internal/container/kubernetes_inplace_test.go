// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package container

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/openrundev/openrun/internal/types"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sapitypes "k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	inPlaceApp     = "pv-app"
	inPlaceOldHash = "old-hash"
	inPlaceNewHash = "new-hash"
)

// inPlaceWrite is one write the fake API server received: the resource, the
// verb and whether it was a server-side dry run
type inPlaceWrite struct {
	resource string
	verb     string
	dryRun   bool
}

// inPlaceFixture is a persistent volume app on the fake cluster: its stable
// Deployment and Service at the old version, with a Ready pod. Writes are
// recorded; a non dry run Deployment apply moves the tracked Deployment to
// the new version, ready (or failed, see failRollout) with a Ready pod, as
// the cluster would
type inPlaceFixture struct {
	client      *k8sfake.Clientset
	k           *KubernetesCM
	writes      []inPlaceWrite
	failRollout bool
}

func newInPlaceFixture(t *testing.T, templateHash string, ready bool) *inPlaceFixture {
	t.Helper()
	replicas := int32(1)
	status := appsv1.DeploymentStatus{ObservedGeneration: 1, UpdatedReplicas: 1, Replicas: 1}
	if ready {
		status.ReadyReplicas = 1
	}
	client := k8sfake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: meta.ObjectMeta{Name: inPlaceApp, Namespace: "apps"},
			Spec: corev1.ServiceSpec{
				Selector: versionSelector(inPlaceApp, inPlaceOldHash),
				Ports:    []corev1.ServicePort{{Port: 8080}},
			},
		},
		&appsv1.Deployment{
			ObjectMeta: meta.ObjectMeta{Name: inPlaceApp, Namespace: "apps", Generation: 1,
				Labels: map[string]string{"app": inPlaceApp}},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Template: corev1.PodTemplateSpec{
					ObjectMeta: meta.ObjectMeta{Labels: versionSelector(inPlaceApp, templateHash)},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: inPlaceApp, Image: "img:" + templateHash}}},
				},
			},
			Status: status,
		},
		&corev1.Pod{
			ObjectMeta: meta.ObjectMeta{Name: inPlaceApp + "-old", Namespace: "apps", Labels: versionSelector(inPlaceApp, inPlaceOldHash)},
			Status: corev1.PodStatus{
				Phase:      corev1.PodRunning,
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			},
		},
	)
	f := &inPlaceFixture{client: client}
	f.k = &KubernetesCM{
		Logger: newTestLogger(), appNamespace: "apps", config: &types.ServerConfig{},
		appConfig: &types.AppConfig{}, clientSet: client, appId: "app_prd_pv",
	}

	record := func(action k8stesting.Action, dryRun []string) {
		f.writes = append(f.writes, inPlaceWrite{
			resource: action.GetResource().Resource, verb: action.GetVerb(), dryRun: len(dryRun) > 0,
		})
	}
	client.PrependReactor("delete", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		record(action, action.(k8stesting.DeleteAction).GetDeleteOptions().DryRun)
		return false, nil, nil
	})
	client.PrependReactor("patch", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		pa, ok := action.(k8stesting.PatchAction)
		if !ok || pa.GetPatchType() != k8sapitypes.ApplyPatchType {
			return false, nil, nil
		}
		opts := action.(k8stesting.PatchActionImpl).PatchOptions
		record(action, opts.DryRun)
		dryRun := len(opts.DryRun) > 0
		switch pa.GetResource().Resource {
		case "services":
			svc := &corev1.Service{
				ObjectMeta: meta.ObjectMeta{Name: pa.GetName(), Namespace: pa.GetNamespace()},
				Spec:       corev1.ServiceSpec{Selector: versionSelector(inPlaceApp, inPlaceNewHash), Ports: []corev1.ServicePort{{Port: 8080}}},
			}
			if !dryRun {
				// Reactors run under the fake's lock: go through the tracker,
				// not the typed client, to read the current object
				gvr := corev1.SchemeGroupVersion.WithResource("services")
				obj, err := client.Tracker().Get(gvr, "apps", pa.GetName())
				if err != nil {
					return true, nil, err
				}
				cur := obj.(*corev1.Service)
				cur.Spec.Selector = svc.Spec.Selector
				if err := client.Tracker().Update(gvr, cur, "apps"); err != nil {
					return true, nil, err
				}
			}
			return true, svc, nil
		case "deployments":
			if dryRun {
				return true, &appsv1.Deployment{ObjectMeta: meta.ObjectMeta{Name: pa.GetName(), Namespace: pa.GetNamespace()}}, nil
			}
			dep, err := f.applyNewVersion(pa.GetName())
			return true, dep, err
		default:
			return true, nil, nil
		}
	})
	return f
}

// applyNewVersion moves the tracked Deployment to the new version, as the
// cluster does for a Deployment apply: rolled out and Ready with a Ready pod,
// or failed when failRollout is set
func (f *inPlaceFixture) applyNewVersion(name string) (*appsv1.Deployment, error) {
	gvr := appsv1.SchemeGroupVersion.WithResource("deployments")
	obj, err := f.client.Tracker().Get(gvr, "apps", name)
	if err != nil {
		return nil, err
	}
	dep := obj.(*appsv1.Deployment).DeepCopy()
	dep.Generation++
	dep.Spec.Template.Labels = versionSelector(inPlaceApp, inPlaceNewHash)
	dep.Spec.Template.Spec.Containers[0].Image = "img:" + inPlaceNewHash
	dep.Status = appsv1.DeploymentStatus{ObservedGeneration: dep.Generation, UpdatedReplicas: 1, ReadyReplicas: 1, Replicas: 1}
	if f.failRollout {
		dep.Status.ReadyReplicas = 0
		dep.Status.UnavailableReplicas = 1
		dep.Status.Conditions = []appsv1.DeploymentCondition{{
			Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse,
			Reason: "ProgressDeadlineExceeded", Message: "pod crash looping",
		}}
	}
	if err := f.client.Tracker().Update(gvr, dep, "apps"); err != nil {
		return nil, err
	}
	if !f.failRollout {
		pod := &corev1.Pod{
			ObjectMeta: meta.ObjectMeta{Name: inPlaceApp + "-new", Namespace: "apps", Labels: versionSelector(inPlaceApp, inPlaceNewHash)},
			Status: corev1.PodStatus{
				Phase:      corev1.PodRunning,
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			},
		}
		if err := f.client.Tracker().Add(pod); err != nil && !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
	}
	return dep, nil
}

func (f *inPlaceFixture) request(t *testing.T, prepare bool) DeployRequest {
	t.Helper()
	return DeployRequest{
		AppEntry:       &types.AppEntry{Id: "app_prd_pv", Path: "/pv", Metadata: types.AppMetadata{VersionMetadata: types.VersionMetadata{Version: 2}}},
		SourceDir:      t.TempDir(),
		ContainerName:  ContainerName(inPlaceApp),
		ImageName:      "img:" + inPlaceNewHash,
		Port:           8080,
		Volumes:        []*VolumeInfo{{VolumeName: "data", TargetPath: "/data"}},
		VersionHash:    inPlaceNewHash,
		Prepare:        prepare,
		DeployAttempts: 2,
	}
}

func (f *inPlaceFixture) deploymentHash(t *testing.T) string {
	t.Helper()
	dep, err := f.client.AppsV1().Deployments("apps").Get(context.Background(), inPlaceApp, meta.GetOptions{})
	if err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	return dep.Spec.Template.Labels[VERSION_HASH_LABEL]
}

func (f *inPlaceFixture) writesOf(verb string) []inPlaceWrite {
	var out []inPlaceWrite
	for _, w := range f.writes {
		if w.verb == verb {
			out = append(out, w)
		}
	}
	return out
}

func assertGone(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("source dir %s should have been removed, stat err=%v", dir, err)
	}
}

// The pre-pass of an operation validates the new version's objects with a
// server-side dry run and leaves the live workload untouched: every write is
// a dry run, nothing registers on the deploy transaction, and the Deployment
// stays at the old version
func TestKubernetesCMInPlacePrepareValidatesWithoutMutating(t *testing.T) {
	f := newInPlaceFixture(t, inPlaceOldHash, true)
	txn := NewDeployTxn()
	ctx := ContextWithDeployTxn(context.Background(), txn)
	req := f.request(t, true)

	result, err := f.k.DeployContainer(ctx, req)
	if err != nil {
		t.Fatalf("DeployContainer: %v", err)
	}
	if result.VersionHash != inPlaceNewHash || result.HostNamePort != "pv-app.apps.svc.cluster.local:8080" {
		t.Fatalf("result = %#v", result)
	}
	if len(f.writes) == 0 {
		t.Fatal("expected dry run writes validating the new version")
	}
	for _, w := range f.writes {
		if !w.dryRun {
			t.Fatalf("pre-pass write %s %s was not a dry run", w.verb, w.resource)
		}
	}
	if txn.Len() != 0 {
		t.Fatalf("pre-pass registered %d deploy entries, want 0", txn.Len())
	}
	if got := f.deploymentHash(t); got != inPlaceOldHash {
		t.Fatalf("deployment hash after pre-pass = %q, want %q (untouched)", got, inPlaceOldHash)
	}
	assertGone(t, req.SourceDir)
}

// The in-transaction deploy of an operation does not touch the workload: it
// registers the rollout as the commit action, which then rolls the
// Deployment out to the new version
func TestKubernetesCMInPlaceOperationDefersRolloutToCommit(t *testing.T) {
	f := newInPlaceFixture(t, inPlaceOldHash, true)
	txn := NewDeployTxn()
	ctx := ContextWithDeployTxn(context.Background(), txn)
	req := f.request(t, false)

	result, err := f.k.DeployContainer(ctx, req)
	if err != nil {
		t.Fatalf("DeployContainer: %v", err)
	}
	if result.VersionHash != inPlaceNewHash || result.HostNamePort != "pv-app.apps.svc.cluster.local:8080" {
		t.Fatalf("result = %#v", result)
	}
	if len(f.writes) != 0 {
		t.Fatalf("in-transaction deploy wrote to the cluster before commit: %+v", f.writes)
	}
	if txn.Len() != 1 {
		t.Fatalf("deploy entries = %d, want 1", txn.Len())
	}
	if txn.CommitBudget() <= 0 {
		t.Fatal("in-place rollout did not register a commit budget")
	}
	if got := f.deploymentHash(t); got != inPlaceOldHash {
		t.Fatalf("deployment hash before commit = %q, want %q", got, inPlaceOldHash)
	}
	if _, err := os.Stat(req.SourceDir); err != nil {
		t.Fatalf("source dir must be kept for the commit rollout: %v", err)
	}

	if err := txn.CommitAll(ctx); err != nil {
		t.Fatalf("CommitAll: %v", err)
	}
	if got := f.deploymentHash(t); got != inPlaceNewHash {
		t.Fatalf("deployment hash after commit = %q, want %q", got, inPlaceNewHash)
	}
	patches := f.writesOf("patch")
	if len(patches) == 0 {
		t.Fatal("commit did not apply the new version")
	}
	for _, w := range patches {
		if w.dryRun {
			t.Fatalf("commit write %s was a dry run", w.resource)
		}
	}
	assertGone(t, req.SourceDir)
}

// A failure elsewhere in the operation rolls the deploy transaction back: the
// workload was never touched, so nothing is restored and only the source dir
// kept for the commit is released
func TestKubernetesCMInPlaceOperationRollbackLeavesWorkloadUntouched(t *testing.T) {
	f := newInPlaceFixture(t, inPlaceOldHash, true)
	txn := NewDeployTxn()
	ctx := ContextWithDeployTxn(context.Background(), txn)
	req := f.request(t, false)

	if _, err := f.k.DeployContainer(ctx, req); err != nil {
		t.Fatalf("DeployContainer: %v", err)
	}
	if err := txn.RollbackAll(ctx); err != nil {
		t.Fatalf("RollbackAll: %v", err)
	}
	if len(f.writes) != 0 {
		t.Fatalf("rollback wrote to the cluster: %+v", f.writes)
	}
	if got := f.deploymentHash(t); got != inPlaceOldHash {
		t.Fatalf("deployment hash after rollback = %q, want %q", got, inPlaceOldHash)
	}
	assertGone(t, req.SourceDir)
}

// A rollout that fails at commit restores the snapshot taken in the
// transaction, and the commit error says so
func TestKubernetesCMInPlaceCommitFailureRestoresPreviousVersion(t *testing.T) {
	f := newInPlaceFixture(t, inPlaceOldHash, true)
	f.failRollout = true
	txn := NewDeployTxn()
	ctx := ContextWithDeployTxn(context.Background(), txn)
	req := f.request(t, false)

	if _, err := f.k.DeployContainer(ctx, req); err != nil {
		t.Fatalf("DeployContainer: %v", err)
	}
	err := txn.CommitAll(ctx)
	if err == nil {
		t.Fatal("CommitAll succeeded, want the rollout failure")
	}
	if !strings.Contains(err.Error(), "the previous version was restored") || !strings.Contains(err.Error(), "pod crash looping") {
		t.Fatalf("commit error = %v, want restored previous version with the rollout failure", err)
	}
	if !ClusterRollbackClean(err) {
		t.Fatalf("commit error = %v, want a clean cluster rollback", err)
	}
	if got := f.deploymentHash(t); got != inPlaceOldHash {
		t.Fatalf("deployment hash after failed commit = %q, want %q (restored)", got, inPlaceOldHash)
	}
	assertGone(t, req.SourceDir)
}

// Inside an operation the snapshot is the only rollback of a rollout that
// fails after the metadata has committed, so a deploy that cannot snapshot
// fails before anything is registered
func TestKubernetesCMInPlaceOperationRequiresSnapshot(t *testing.T) {
	f := newInPlaceFixture(t, inPlaceOldHash, true)
	f.client.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("secrets forbidden")
	})
	txn := NewDeployTxn()
	ctx := ContextWithDeployTxn(context.Background(), txn)
	req := f.request(t, false)

	_, err := f.k.DeployContainer(ctx, req)
	if err == nil || !strings.Contains(err.Error(), "failed to capture rollback snapshot") {
		t.Fatalf("DeployContainer error = %v, want snapshot failure", err)
	}
	if len(f.writes) != 0 || txn.Len() != 0 {
		t.Fatalf("writes = %+v entries = %d, want none", f.writes, txn.Len())
	}
	if got := f.deploymentHash(t); got != inPlaceOldHash {
		t.Fatalf("deployment hash = %q, want %q", got, inPlaceOldHash)
	}
	assertGone(t, req.SourceDir)
}

// Outside an operation a rollout of the requested version already submitted
// (a commit still waiting for it) is joined: the spec is re-applied without a
// snapshot and the rollout waited for
func TestKubernetesCMInPlaceStandaloneJoinsRolloutInProgress(t *testing.T) {
	f := newInPlaceFixture(t, inPlaceNewHash, false)
	req := f.request(t, false)

	result, err := f.k.DeployContainer(context.Background(), req)
	if err != nil {
		t.Fatalf("DeployContainer: %v", err)
	}
	if result.HostNamePort != "pv-app.apps.svc.cluster.local:8080" || result.VersionHash != inPlaceNewHash {
		t.Fatalf("result = %#v", result)
	}
	for _, action := range f.client.Actions() {
		if action.GetVerb() == "list" && action.GetResource().Resource == "secrets" {
			t.Fatal("joined rollout took a snapshot")
		}
	}
	if len(f.writesOf("patch")) == 0 {
		t.Fatal("joined rollout did not re-apply the version")
	}
	if got := f.deploymentHash(t); got != inPlaceNewHash {
		t.Fatalf("deployment hash = %q, want %q", got, inPlaceNewHash)
	}
	assertGone(t, req.SourceDir)
}

// Outside an operation the rollout runs immediately, snapshotting first so a
// failure restores the previous version
func TestKubernetesCMInPlaceStandaloneRollsOutImmediately(t *testing.T) {
	f := newInPlaceFixture(t, inPlaceOldHash, true)
	req := f.request(t, false)

	if _, err := f.k.DeployContainer(context.Background(), req); err != nil {
		t.Fatalf("DeployContainer: %v", err)
	}
	if got := f.deploymentHash(t); got != inPlaceNewHash {
		t.Fatalf("deployment hash = %q, want %q", got, inPlaceNewHash)
	}
	assertGone(t, req.SourceDir)

	failing := newInPlaceFixture(t, inPlaceOldHash, true)
	failing.failRollout = true
	req = failing.request(t, false)
	_, err := failing.k.DeployContainer(context.Background(), req)
	if err == nil || !ClusterRollbackClean(err) {
		t.Fatalf("failed standalone rollout error = %v, want a clean rollback", err)
	}
	if got := failing.deploymentHash(t); got != inPlaceOldHash {
		t.Fatalf("deployment hash after failed rollout = %q, want %q (restored)", got, inPlaceOldHash)
	}
}

func TestDryRunOption(t *testing.T) {
	ctx := context.Background()
	if got := dryRunOption(ctx); got != nil {
		t.Fatalf("dryRunOption(plain ctx) = %v, want nil", got)
	}
	k := &KubernetesCM{}
	if got := k.applyOptions(ctx).DryRun; got != nil {
		t.Fatalf("applyOptions(plain ctx).DryRun = %v, want nil", got)
	}
	dry := withServerDryRun(ctx)
	if got := dryRunOption(dry); len(got) != 1 || got[0] != meta.DryRunAll {
		t.Fatalf("dryRunOption(dry run ctx) = %v, want [All]", got)
	}
	if got := k.applyOptions(dry).DryRun; len(got) != 1 || got[0] != meta.DryRunAll {
		t.Fatalf("applyOptions(dry run ctx).DryRun = %v, want [All]", got)
	}
}
