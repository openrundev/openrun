// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
	"github.com/openrundev/openrun/internal/types"
)

func TestStoreBasics(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
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
		if ret4.error.index("UNIQUE constraint failed") < 0:
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
	`,

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

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"store.in"},
		[]types.Permission{
			{Plugin: "store.in", Method: "insert"},
			{Plugin: "store.in", Method: "select_by_id"},
			{Plugin: "store.in", Method: "update"},
			{Plugin: "store.in", Method: "delete_by_id"},
			{Plugin: "store.in", Method: "select"},
			{Plugin: "store.in", Method: "delete"},
			{Plugin: "store.in", Method: "count"},
			{Plugin: "store.in", Method: "select_one"},
		}, map[string]types.PluginSettings{
			"store.in": {
				"db_connection": "sqlite:/tmp/openrun_app.db?_journal_mode=WAL",
			},
		})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

	request := httptest.NewRequest("GET", "/test", nil)
	response := httptest.NewRecorder()
	a.ServeHTTP(response, request)

	testutil.AssertEqualsInt(t, "code", 200, response.Code)

	ret := make(map[string]any)
	str := response.Body.String()
	fmt.Print(str)
	json.NewDecoder(response.Body).Decode(&ret) //nolint:errcheck

	if _, ok := ret["error"]; ok {
		t.Fatal(ret["error"])
	}

	testutil.AssertEqualsString(t, "creator", "admin", ret["creator"].(string))
	testutil.AssertEqualsString(t, "astring", "xyz", ret["stringval"].(string))
	id := ret["_id"].(float64)
	if id <= 0 {
		t.Errorf("Expected _id to be > 0, got %f", id)
	}
	testutil.AssertEqualsInt(t, "length", 3, len(ret["all_rows"].([]any)))
	rows := ret["all_rows"].([]any)
	if rows[0].(map[string]any)["aint"].(float64) != 100 {
		t.Errorf("Expected aint to be 100, got %f", rows[0].(map[string]any)["aint"].(float64))
	}
	if rows[1].(map[string]any)["aint"].(float64) != 20 {
		t.Errorf("Expected aint to be 20, got %f", rows[0].(map[string]any)["aint"].(float64))
	}
}

func TestStoreTransaction(t *testing.T) {
	logger := testutil.TestLogger()
	fileData := map[string]string{
		"app.star": `
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

	a, _, err := CreateTestAppPlugin(logger, fileData, []string{"store.in"},
		[]types.Permission{
			{Plugin: "store.in", Method: "insert"},
			{Plugin: "store.in", Method: "begin"},
			{Plugin: "store.in", Method: "commit"},
			{Plugin: "store.in", Method: "rollback"},
			{Plugin: "store.in", Method: "select"},
			{Plugin: "store.in", Method: "delete"},
			{Plugin: "store.in", Method: "count"},
			{Plugin: "store.in", Method: "select_one"},
		}, map[string]types.PluginSettings{
			"store.in": {
				"db_connection": "sqlite:/tmp/openrun_app.db?_journal_mode=WAL",
			},
		})
	if err != nil {
		t.Fatalf("Error %s", err)
	}

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
	testutil.AssertStringContains(t, response.Body.String(), "resource has not be closed, check handler code: store.in:rows_cursor")

	// Select with leak - html endpoint
	request = httptest.NewRequest("GET", "/test/select_leak_html", nil)
	response = httptest.NewRecorder()
	a.ServeHTTP(response, request)
	testutil.AssertEqualsInt(t, "code", 500, response.Code)
	testutil.AssertStringContains(t, response.Body.String(), "resource has not be closed, check handler code: store.in:rows_cursor")
}
