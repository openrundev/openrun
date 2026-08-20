// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/openrundev/openrun/internal/app"
	"github.com/openrundev/openrun/internal/app/store"
	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

// buildStoreProvider builds the external store plugin provider binary once
// per test and registers it, so the same store tests can run against
// "store.ex" (out-of-process) as well as "store.in" (builtin).
func buildStoreProvider(t *testing.T) {
	t.Helper()
	execPath := filepath.Join(t.TempDir(), "openrun-plugin-store")
	cmd := exec.Command("go", "build", "-o", execPath, "./internal/app/store/storeprovider")
	cmd.Dir = "../../.."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("error building store provider: %v\n%s", err, out)
	}
	if err := app.RegisterExternalProvider("store-test", execPath, ""); err != nil {
		t.Fatalf("error registering store provider: %v", err)
	}
	t.Cleanup(func() { app.UnregisterExternalProvider("store-test") })
}

func runStoreBasicsTest(t *testing.T, module, dbConnection string, expectedDupErr string) {
	t.Helper()

	logger := testutil.TestLogger()
	storeScript := strings.ReplaceAll(`
load("store.in", "store")

app = ace.app("testApp", custom_layout=True, routes  = [ace.api("/")],
permissions=[
	ace.permission("store.in", "insert"),
	ace.permission("store.in", "select_by_id"),
	ace.permission("store.in", "update"),
	ace.permission("store.in", "delete_by_id"),
	ace.permission("store.in", "select"),
	ace.permission("store.in", "delete"),
	ace.permission("store.in", "count"),
	ace.permission("store.in", "select_one"),
]
)

def handler(req):

	rows = store.delete(table.test1, {})
	myt = doc.test1(aint=10, astring="abc", abool=False, alist=[1], adict={'a': 1})
	ret = store.insert(table.test1, myt)
	if not ret:
		return {"error": ret.error}
	myt.aint=20
	ret2 = store.insert(table.test1, myt)
	if not ret2:
		return {"error": ret2.error}
	myt.aint=30
	myt.adict = {"a": 2}
	ret3 = store.insert(table.test1, myt)
	if not ret3:
		return {"error": ret3.error}
	ret4 = store.insert(table.test1, myt)
	if ret4: # Expect to fail
		return {"error": "Expected duplicate insert to fail"}
	else:
		if ret4.error.index(__DUPLICATE_SUBSTR__) < 0:
			return {"error": ret4.error}

	id = ret.value
	ret = store.select_by_id(table.test1, id)
	if not ret:
		return {"error": ret.error}

	f = ret.value
	f.aint = 100
	f.astring = "xyz"

	upd_status = store.update(table.test1, f)
	if not upd_status:
		return {"error": ret.error}

	# Duplicate updates should fail (optimistic locking)
	upd_status = store.update(table.test1, f)
	if upd_status:
		return {"error": "Expected duplicate update to fail"}

	q1 = store.count(table.test1, {"aint": 100})
	if not q1:
		return {"error": q1.error}
	if q1.value != 1:
		return {"error": "Expected count to be 1, got %d" % q1.value}

	q2 = store.count(table.test1, {"adict.a": 2})
	if not q2:
		return {"error": q2.error}
	#if q2.value != 1:
	#	return {"error": "2Expected count to be 1, got %d" % q2.value}

	select_one = store.select_one(table.test1, {"aint": 100})
	if not select_one:
		return {"error": select_one.error}
	if select_one.value.aint != 100 or select_one.value.astring != "xyz":
		return {"error": "Expected aint 100 astring xyz, got %d %s" % (select_one.value.aint, select_one.value.astring)}

	select_multi = store.select(table.test1, {"$or": [{"aint": 100}, {"aint": 20}]})
	if not select_multi:
		return {"error": select_multi.error}
	for row in select_multi.value:
		break # Close result set

	ret = store.select_by_id(table.test1, id)

	select_result = store.select(table.test1, {})

	all_rows = []
	for row in select_result.value:
		all_rows.append(row)

	select_result = store.select(table.test1, {}, sort=["aint:asc"])
	if not select_result:
		return {"error": select_result.error}
	index = 0
	for row in select_result.value:
		if row.aint != 20:
			return {"error": "Expected first aint to be 20, got %d" % row.aint}
		break

	del_status = store.delete_by_id(table.test1, id)
	if not del_status:
		return {"error": del_status.error}
	del_status = store.delete_by_id(table.test1, id)
	if del_status:
		return {"error": "Expected delete to fail"}

	return {"intval": ret.value.aint, "stringval": ret.value.astring,
		"_id": ret.value._id,
		"creator": ret.value._created_by, "created_at": ret.value._created_at,
	    "all_rows": all_rows}
`, "__DUPLICATE_SUBSTR__", strconv.Quote(expectedDupErr))
	storeScript = strings.ReplaceAll(storeScript, `"store.in"`, `"`+module+`"`)

	fileData := map[string]string{
		"app.star": storeScript,

		"schema.star": `
type("test1", fields=[
    field("aint", INT),
    field("astring", STRING),
    field("abool", BOOLEAN),
    field("alist", LIST),
    field("adict", DICT),
],
indexes=[
	index(["aint:asc", "astring:desc"], unique=True)
	])`,
		"index.go.html": ``,
	}

	// Remove old db file if exists
	os.Remove("/tmp/openrun_app.db")     //nolint:errcheck
	os.Remove("/tmp/openrun_app.db-wal") //nolint:errcheck
	os.Remove("/tmp/openrun_app.db-shm") //nolint:errcheck

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{module},
		[]types.Permission{
			{Plugin: module, Method: "insert"},
			{Plugin: module, Method: "select_by_id"},
			{Plugin: module, Method: "update"},
			{Plugin: module, Method: "delete_by_id"},
			{Plugin: module, Method: "select"},
			{Plugin: module, Method: "delete"},
			{Plugin: module, Method: "count"},
			{Plugin: module, Method: "select_one"},
		}, map[string]types.PluginSettings{
			module: {
				"db_connection": dbConnection,
			},
		})
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	defer a.Close() //nolint:errcheck

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	if response.Code != 200 {
		t.Fatalf("unexpected response code %d body %s", response.Code, response.Body.String())
	}

	ret := make(map[string]any)
	str := response.Body.String()
	fmt.Print(str)
	json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck

	if _, ok := ret["error"]; ok {
		t.Fatal(ret["error"])
	}

	creator, ok := ret["creator"].(string)
	if !ok {
		t.Fatalf("missing or invalid creator in response: %#v", ret)
	}
	testutil.AssertEqualsString(t, "creator", "admin", creator)

	stringVal, ok := ret["stringval"].(string)
	if !ok {
		t.Fatalf("missing or invalid stringval in response: %#v", ret)
	}
	testutil.AssertEqualsString(t, "astring", "xyz", stringVal)

	id, ok := ret["_id"].(float64)
	if !ok {
		t.Fatalf("missing or invalid _id in response: %#v", ret)
	}
	if id <= 0 {
		t.Errorf("Expected _id to be > 0, got %f", id)
	}

	rows, ok := ret["all_rows"].([]any)
	if !ok {
		t.Fatalf("missing or invalid all_rows in response: %#v", ret)
	}
	testutil.AssertEqualsInt(t, "length", 3, len(rows))
	aintValues := make(map[int]int)
	for _, row := range rows {
		rowMap, ok := row.(map[string]any)
		if !ok {
			t.Fatalf("invalid row type: %#v", row)
		}
		aint, ok := rowMap["aint"].(float64)
		if !ok {
			t.Fatalf("missing or invalid aint in row: %#v", rowMap)
		}
		aintValues[int(aint)]++
	}
	if aintValues[100] != 1 {
		t.Errorf("Expected one row with aint=100, got counts %#v", aintValues)
	}
	if aintValues[20] != 1 {
		t.Errorf("Expected one row with aint=20, got counts %#v", aintValues)
	}
}

func TestStoreBasics(t *testing.T) {
	// Remove old db file if exists
	os.Remove("/tmp/openrun_app.db")     //nolint:errcheck
	os.Remove("/tmp/openrun_app.db-wal") //nolint:errcheck
	os.Remove("/tmp/openrun_app.db-shm") //nolint:errcheck

	runStoreBasicsTest(t, "store.in", "sqlite:/tmp/openrun_app.db?_journal_mode=WAL", "UNIQUE constraint failed")
}

func TestStoreBasicsExternal(t *testing.T) {
	// Same test cases as TestStoreBasics, with the store plugin served by the
	// out-of-process provider as store.ex
	buildStoreProvider(t)

	// Remove old db file if exists
	os.Remove("/tmp/openrun_app.db")     //nolint:errcheck
	os.Remove("/tmp/openrun_app.db-wal") //nolint:errcheck
	os.Remove("/tmp/openrun_app.db-shm") //nolint:errcheck

	runStoreBasicsTest(t, "store.ex", "sqlite:/tmp/openrun_app.db?_journal_mode=WAL", "UNIQUE constraint failed")
}

func TestStoreBasicsExternalFallbackForIn(t *testing.T) {
	// Same test cases as TestStoreBasics, loading "store.in" in a binary with
	// no compiled-in store module: resolution falls back to the external
	// provider, so apps do not change between internal and external builds
	buildStoreProvider(t)

	app.UnregisterLocalProvider("store")
	t.Cleanup(func() {
		app.RegisterLocalProvider("store", store.ProviderConfig("builtin"), app.LocalProviderOptions{})
	})

	// Remove old db file if exists
	os.Remove("/tmp/openrun_app.db")     //nolint:errcheck
	os.Remove("/tmp/openrun_app.db-wal") //nolint:errcheck
	os.Remove("/tmp/openrun_app.db-shm") //nolint:errcheck

	runStoreBasicsTest(t, "store.in", "sqlite:/tmp/openrun_app.db?_journal_mode=WAL", "UNIQUE constraint failed")
}

func TestStoreBasicsPostgresTestcontainer(t *testing.T) {
	if os.Getenv("ENABLE_POSTGRES_TESTCONTAINER") == "" {
		t.Skip("set ENABLE_POSTGRES_TESTCONTAINER=1 to run postgres testcontainer store basics test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	connStr, cleanup, err := testutil.StartPostgresContainer(ctx, "postgres:17-alpine", "openrun_store", "postgres", "postgres")
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}
	defer cleanup()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer readyCancel()
	if err := waitForPostgresReady(readyCtx, connStr); err != nil {
		t.Fatalf("postgres container did not become ready: %v", err)
	}

	runStoreBasicsTest(t, "store.in", connStr, "duplicate key value violates unique constraint")
}

func waitForPostgresReady(ctx context.Context, connStr string) error {
	var lastErr error
	for {
		db, err := sql.Open("pgx", connStr)
		if err == nil {
			pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err = db.PingContext(pingCtx)
			cancel()
			db.Close() //nolint:errcheck
			if err == nil {
				return nil
			}
		}
		lastErr = err

		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("last error: %w", lastErr)
			}
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}

func TestStoreTransaction(t *testing.T) {
	runStoreTransactionTest(t, "store.in")
}

func TestStoreTransactionExternal(t *testing.T) {
	// Same test cases as TestStoreTransaction (including the cursor leak
	// checks), with the store plugin served out-of-process as store.ex
	buildStoreProvider(t)
	runStoreTransactionTest(t, "store.ex")
}

func runStoreTransactionTest(t *testing.T, module string) {
	t.Helper()

	logger := testutil.TestLogger()
	appScript := `
load("store.in", "store")

def create(req):
	store.begin()

	store.delete(table.mytype, {}) # clear all

	myt = doc.mytype(c1=10, c2="abc")

	ret = store.insert(table.mytype, myt)
	if not ret:
		return {"error": ret.error}

	store.commit()
	return {"id": ret.value}

def count(req):
	ret = store.count(table.mytype, {})
	if not ret:
		return {"error": ret.error}
	return {"count": ret.value}

def create_no_commit(req):
	store.begin()
	myt = doc.mytype(c1=20, c2="def")

	ret = store.insert(table.mytype, myt)
	if not ret:
		return {"error": ret.error}

	return {}

def select(req):
	ret = store.select_one(table.mytype, {})
	if not ret:
		return {"error": ret.error}

	return ret.value

def create_rollback(req):
	store.begin()
	myt = doc.mytype(c1=20, c2="def")

	ret = store.insert(table.mytype, myt)
	if not ret:
		return {"error": ret.error}
	store.rollback()

	return {}

def select_leak(req):
	ret = store.select(table.mytype, {})
	if not ret:
		return {"error": ret.error}

	# Not accessing the cursor
	return {}

app = ace.app("testApp", custom_layout=True, 
	routes = [ace.api("/create", handler=create),
			ace.api("/select", handler=select),
			ace.api("/count", handler=count),
			ace.api("/create_no_commit", handler=create_no_commit),
			ace.api("/create_rollback", handler=create_rollback),
			ace.api("/select_leak", handler=select_leak),
			ace.html("/select_leak_html", handler=select_leak)],
	permissions=[
		ace.permission("store.in", "insert"),
		ace.permission("store.in", "begin"),
		ace.permission("store.in", "commit"),
		ace.permission("store.in", "collback"),
		ace.permission("store.in", "select"),
		ace.permission("store.in", "delete"),
		ace.permission("store.in", "count"),
		ace.permission("store.in", "select_one"),
	]
)`
	appScript = strings.ReplaceAll(appScript, `"store.in"`, `"`+module+`"`)

	fileData := map[string]string{
		"app.star": appScript,

		"schema.star": `
type("mytype", fields=[
    field("c1", INT),
    field("c2", STRING),
])`,
		"index.go.html": ``,
	}

	// Remove old db file if exists
	os.Remove("/tmp/openrun_app.db")     //nolint:errcheck
	os.Remove("/tmp/openrun_app.db-wal") //nolint:errcheck
	os.Remove("/tmp/openrun_app.db-shm") //nolint:errcheck

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{module},
		[]types.Permission{
			{Plugin: module, Method: "insert"},
			{Plugin: module, Method: "begin"},
			{Plugin: module, Method: "commit"},
			{Plugin: module, Method: "rollback"},
			{Plugin: module, Method: "select"},
			{Plugin: module, Method: "delete"},
			{Plugin: module, Method: "count"},
			{Plugin: module, Method: "select_one"},
		}, map[string]types.PluginSettings{
			module: {
				"db_connection": "sqlite:/tmp/openrun_app.db?_journal_mode=WAL",
			},
		})
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	defer a.Close() //nolint:errcheck

	request := httptest.NewRequest("GET", "/test/create", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	ret := make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck

	if _, ok := ret["error"]; ok {
		t.Fatal(ret["error"])
	}

	id := ret["id"]
	if id.(float64) <= 0 {
		t.Errorf("Expected _id to be > 0, got %f", id)
	}

	request = httptest.NewRequest("GET", "/test/select", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	ret = make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck

	if _, ok := ret["error"]; ok {
		t.Fatal(ret["error"])
	}

	fmt.Printf("ret %v\n", ret)
	testutil.AssertEqualsString(t, "c2", "abc", ret["c2"].(string))
	fmt.Printf("ret %v\n", ret)

	// Create without commit
	request = httptest.NewRequest("GET", "/test/create_no_commit", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	// Get count
	request = httptest.NewRequest("GET", "/test/count", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	ret = make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck

	if _, ok := ret["error"]; ok {
		t.Fatal(ret["error"])
	}

	// Count should be 1
	testutil.AssertEqualsInt(t, "count", 1, int(ret["count"].(float64)))

	// Create roll back
	request = httptest.NewRequest("GET", "/test/create_rollback", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	// Get count
	request = httptest.NewRequest("GET", "/test/count", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	ret = make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck

	if _, ok := ret["error"]; ok {
		t.Fatal(ret["error"])
	}

	// Count should be 1
	testutil.AssertEqualsInt(t, "count", 1, int(ret["count"].(float64)))

	// Select with leak
	request = httptest.NewRequest("GET", "/test/select_leak", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "resource has not be closed, check handler code: "+module+":rows_cursor")

	// Select with leak - html endpoint
	request = httptest.NewRequest("GET", "/test/select_leak_html", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "resource has not be closed, check handler code: "+module+":rows_cursor")
}

// TestStoreMixedPlugins loads the builtin store.in and the external store.ex
// in the same app (sharing one database) and verifies the cross-plugin
// request-level contracts: an unchecked error from an external plugin call
// blocks the next call to a builtin plugin (shared TL_PLUGIN_API_FAILED_ERROR
// semantics), and request-end deferred cleanup drains both plugins' entries —
// the builtin cursor leak fails the request while the external provider's
// uncommitted transaction still rolls back via EndSession.
func TestStoreMixedPlugins(t *testing.T) {
	buildStoreProvider(t)

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
load("store.in", "store")
load("store.ex", store_ex="store")

def setup(req):
	store.delete(table.mytype, {})
	myt = doc.mytype(c1=1, c2="a")
	ret = store.insert(table.mytype, myt)
	if not ret:
		return {"error": ret.error}
	return {}

def err_cross(req):
	ret = store_ex.select_by_id(table.mytype, 9999999) # fails, error not checked
	ret2 = store.count(table.mytype, {}) # builtin call must be blocked
	return {"count": ret2.value}

def defer_cross(req):
	store_ex.begin()
	myt = doc.mytype(c1=2, c2="b")
	ret = store_ex.insert(table.mytype, myt)
	if not ret:
		return {"error": ret.error}
	# leak a builtin cursor in the same request: the request must fail with
	# the store.in leak error, and the store.ex transaction must roll back
	store.select(table.mytype, {})
	return {}

def count(req):
	ret = store_ex.count(table.mytype, {})
	if not ret:
		return {"error": ret.error}
	return {"count": ret.value}

def cursor_cross(req):
	# obtain an external cursor, call a builtin plugin, then iterate: the
	# cursor's strict cleanup entry must be cleared under its own module even
	# though the current module changed in between
	ret = store_ex.select(table.mytype, {})
	cnt = store.count(table.mytype, {})
	rows = []
	for row in ret.value:
		rows.append(row)
	return {"count": cnt.value, "rows": len(rows)}

def cursor_cross_rev(req):
	# same in the other direction: builtin cursor, external call, iterate
	ret = store.select(table.mytype, {})
	cnt = store_ex.count(table.mytype, {})
	rows = []
	for row in ret.value:
		rows.append(row)
	return {"count": cnt.value, "rows": len(rows)}

app = ace.app("testApp", custom_layout=True,
	routes = [ace.api("/setup", handler=setup),
		ace.api("/err_cross", handler=err_cross),
		ace.api("/defer_cross", handler=defer_cross),
		ace.api("/cursor_cross", handler=cursor_cross),
		ace.api("/cursor_cross_rev", handler=cursor_cross_rev),
		ace.api("/count", handler=count)],
	permissions=[
		ace.permission("store.in", "insert"),
		ace.permission("store.in", "delete"),
		ace.permission("store.in", "count"),
		ace.permission("store.in", "select"),
		ace.permission("store.ex", "select_by_id"),
		ace.permission("store.ex", "begin"),
		ace.permission("store.ex", "insert"),
		ace.permission("store.ex", "count"),
		ace.permission("store.ex", "select"),
	]
)`,

		"schema.star": `
type("mytype", fields=[
    field("c1", INT),
    field("c2", STRING),
])`,
		"index.go.html": ``,
	}

	// Remove old db file if exists
	os.Remove("/tmp/openrun_app.db")     //nolint:errcheck
	os.Remove("/tmp/openrun_app.db-wal") //nolint:errcheck
	os.Remove("/tmp/openrun_app.db-shm") //nolint:errcheck

	dbConnection := "sqlite:/tmp/openrun_app.db?_journal_mode=WAL"
	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"store.in", "store.ex"},
		[]types.Permission{
			{Plugin: "store.in", Method: "insert"},
			{Plugin: "store.in", Method: "delete"},
			{Plugin: "store.in", Method: "count"},
			{Plugin: "store.in", Method: "select"},
			{Plugin: "store.ex", Method: "select_by_id"},
			{Plugin: "store.ex", Method: "begin"},
			{Plugin: "store.ex", Method: "insert"},
			{Plugin: "store.ex", Method: "count"},
			{Plugin: "store.ex", Method: "select"},
		}, map[string]types.PluginSettings{
			"store.in": {"db_connection": dbConnection},
			"store.ex": {"db_connection": dbConnection},
		})
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	defer a.Close() //nolint:errcheck

	// Seed one row through the builtin plugin
	request := httptest.NewRequest("GET", "/test/setup", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	// Unchecked external plugin error blocks the following builtin call
	request = httptest.NewRequest("GET", "/test/err_cross", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "previous plugin call failed")

	// Mixed deferred cleanup: builtin cursor leak fails the request...
	request = httptest.NewRequest("GET", "/test/defer_cross", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "resource has not be closed, check handler code: store.in:rows_cursor")

	// Cross-module cursor iteration: another plugin called between select and
	// the iteration must not break the cursor's leak-entry cleanup
	for _, path := range []string{"/test/cursor_cross", "/test/cursor_cross_rev"} {
		request = httptest.NewRequest("GET", path, nil)
		response = httptest.NewRecorder()
		a.ServeHTTP(response, request)
		testutil.AssertEqualsInt(t, "code "+path, 200, response.Code)
		crossRet := make(map[string]any)
		json.NewDecoder(response.Body).Decode(&crossRet) //nolint:errcheck
		if _, ok := crossRet["error"]; ok {
			t.Fatal(crossRet["error"])
		}
		testutil.AssertEqualsInt(t, "rows "+path, 1, int(crossRet["rows"].(float64)))
	}

	// ...and the external provider's uncommitted transaction rolled back:
	// the count (via store.ex) is still 1
	request = httptest.NewRequest("GET", "/test/count", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	ret := make(map[string]any)
	json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck
	if _, ok := ret["error"]; ok {
		t.Fatal(ret["error"])
	}
	testutil.AssertEqualsInt(t, "count", 1, int(ret["count"].(float64)))
}

// TestStoreExternalReload verifies the provider process restart on app
// reload: providers launched before (or during) a reload are stopped when the
// new app state is published, and the next call relaunches a fresh process
// from the reloaded state.
func TestStoreExternalReload(t *testing.T) {
	buildStoreProvider(t)

	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
load("store.ex", "store")

def handler(req):
	store.delete(table.mytype, {})
	myt = doc.mytype(c1=10, c2="abc")
	ret = store.insert(table.mytype, myt)
	if not ret:
		return {"error": ret.error}
	cnt = store.count(table.mytype, {})
	return {"count": cnt.value}

app = ace.app("testApp", custom_layout=True, routes = [ace.api("/")],
	permissions=[
		ace.permission("store.ex", "insert"),
		ace.permission("store.ex", "delete"),
		ace.permission("store.ex", "count"),
	]
)`,
		"schema.star": `
type("mytype", fields=[
    field("c1", INT),
    field("c2", STRING),
])`,
		"index.go.html": ``,
	}

	// Remove old db file if exists
	os.Remove("/tmp/openrun_app.db")     //nolint:errcheck
	os.Remove("/tmp/openrun_app.db-wal") //nolint:errcheck
	os.Remove("/tmp/openrun_app.db-shm") //nolint:errcheck

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"store.ex"},
		[]types.Permission{
			{Plugin: "store.ex", Method: "insert"},
			{Plugin: "store.ex", Method: "delete"},
			{Plugin: "store.ex", Method: "count"},
		}, map[string]types.PluginSettings{
			"store.ex": {"db_connection": "sqlite:/tmp/openrun_app.db?_journal_mode=WAL"},
		})
	if err != nil {
		t.Fatalf("Error %s", err)
	}
	defer a.Close() //nolint:errcheck

	runRequest := func() {
		t.Helper()
		request := httptest.NewRequest("GET", "/test", nil)
		response := httptest.NewRecorder()
		a.ServeHTTP(response, request)
		testutil.AssertEqualsInt(t, "code", 200, response.Code)
		ret := make(map[string]any)
		json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck
		if _, ok := ret["error"]; ok {
			t.Fatal(ret["error"])
		}
		testutil.AssertEqualsInt(t, "count", 1, int(ret["count"].(float64)))
	}

	// Launch the provider through a request, then force a reload (which stops
	// the provider process after publishing the new state) and verify the
	// next request relaunches and works
	runRequest()
	if _, err := a.Reload(context.Background(), true, true, types.DryRunFalse, app.ReloadOptions{}); err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	runRequest()
}
