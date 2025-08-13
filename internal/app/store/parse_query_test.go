// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"slices"
	"testing"

	"github.com/openrundev/openrun/internal/testutil"
)

func ParseQueryTest(t *testing.T, query map[string]any, expectedConditions string, expectedParams []any) {
	t.Helper()
	conditions, params, err := parseQuery(query, nil)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if conditions != expectedConditions {
		t.Errorf("Conditions do not match. Expected: %s, Got: %s.", expectedConditions, conditions)
	}

	if !slices.Equal(params, expectedParams) {
		t.Errorf("Params do not match. Expected: %v, Got: %v.", expectedParams, params)
	}
}

func ParseQueryMapperTest(t *testing.T, query map[string]any, expectedConditions string, expectedParams []any) {
	t.Helper()
	conditions, params, err := parseQuery(query, sqliteFieldMapper)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if conditions != expectedConditions {
		t.Errorf("Conditions do not match. Expected: %s, Got: %s.", expectedConditions, conditions)
	}

	if !slices.Equal(params, expectedParams) {
		t.Errorf("Params do not match. Expected: %v, Got: %v.", expectedParams, params)
	}
}

func ParseQueryErrorTest(t *testing.T, query map[string]any, expected string) {
	t.Helper()
	_, _, err := parseQuery(query, nil)
	testutil.AssertErrorContains(t, err, expected)
}

func ParseMappedErrorTest(t *testing.T, query map[string]any, expected string) {
	t.Helper()
	_, _, err := parseQuery(query, sqliteFieldMapper)
	testutil.AssertErrorContains(t, err, expected)
}
func TestEqualityQueries(t *testing.T) {
	ParseQueryTest(t, nil, "", nil)
	ParseQueryTest(t, map[string]any{}, "", nil)
	ParseQueryTest(t, map[string]any{"age": 30}, "age = ?", []any{30})
	ParseQueryTest(t, map[string]any{"age": 30, "city": "New York"}, "age = ? AND city = ?", []any{30, "New York"})
	ParseQueryTest(t, map[string]any{"age": 30, "city": "New York", "state": "California"}, "age = ? AND city = ? AND state = ?", []any{30, "New York", "California"})
	ParseQueryTest(t, map[string]any{"age": 30, "city": "New York", "state": "California", "country": "USA"}, "age = ? AND city = ? AND country = ? AND state = ?", []any{30, "New York", "USA", "California"})
	ParseQueryTest(t, map[string]any{"age": 30, "$or": []map[string]any{{"city": "New York"}, {"state": "California"}}}, " ( city = ? OR state = ? )  AND age = ?", []any{"New York", "California", 30})
	ParseQueryTest(t, map[string]any{"age": 30, "$or": []map[string]any{{"city": "New York"}, {"state": "California"}}}, " ( city = ? OR state = ? )  AND age = ?", []any{"New York", "California", 30})
	ParseQueryTest(t, map[string]any{"age": 30, "$or": []map[string]any{{"city": "New York"}}}, " ( city = ? )  AND age = ?", []any{"New York", 30})
	ParseQueryTest(t, map[string]any{"age": 30, "$or": []map[string]any{{"city": "New York"}, {"state": "California"}, {"country": "USA"}}}, " ( city = ? OR state = ? OR country = ? )  AND age = ?", []any{"New York", "California", "USA", 30})
	ParseQueryTest(t, map[string]any{"age": 30, "$and": []map[string]any{{"city": "New York"}, {"state": "California"}}, "country": "USA"}, " ( city = ? AND state = ? )  AND age = ? AND country = ?", []any{"New York", "California", 30, "USA"})
	ParseQueryTest(t, map[string]any{"age": 30, "$AND": []map[string]any{{"city": "New York"}, {"$OR": []map[string]any{{"state": "California"}, {"country": "USA"}}}, {"city": "New York"}}}, " ( city = ? AND  ( state = ? OR country = ? )  AND city = ? )  AND age = ?", []any{"New York", "California", "USA", "New York", 30})
}

func TestOperatorQueries(t *testing.T) {
	ParseQueryTest(t, map[string]any{"age": map[string]any{"$gt": 30}}, "age > ?", []any{30})
	ParseQueryTest(t, map[string]any{"age": map[string]any{"$lt": 30}}, "age < ?", []any{30})
	ParseQueryTest(t, map[string]any{"age": map[string]any{"$gte": 30}}, "age >= ?", []any{30})
	ParseQueryTest(t, map[string]any{"age": map[string]any{"$lte": 30}}, "age <= ?", []any{30})
	ParseQueryTest(t, map[string]any{"age": map[string]any{"$ne": 30}}, "age != ?", []any{30})
	ParseQueryTest(t, map[string]any{"age": map[string]any{"$eq": 30}}, "age = ?", []any{30})
	ParseQueryTest(t, map[string]any{"age": map[string]any{"$like": 30}}, "age like ?", []any{30})
}

func TestMultiOperatorQueries(t *testing.T) {
	ParseQueryTest(t, map[string]any{"age": map[string]any{"$gt": 30, "$lt": 40}}, "age > ? AND age < ?", []any{30, 40})
	ParseQueryTest(t, map[string]any{"age": map[string]any{"$gt": 30, "$lt": 40, "$ne": 35}}, "age > ? AND age < ? AND age != ?", []any{30, 40, 35})
	ParseQueryTest(t, map[string]any{"city": "New York", "age": map[string]any{"$gt": 30, "$lt": 40, "$ne": 35}}, "age > ? AND age < ? AND age != ? AND city = ?", []any{30, 40, 35, "New York"})
	ParseQueryTest(t, map[string]any{"age": map[string]any{"$gt": 30, "$lt": 40, "$and": []map[string]any{{"$ne": 34}, {"$ne": 35}}}}, " ( age != ? AND age != ? )  AND age > ? AND age < ?", []any{34, 35, 30, 40})
}

func TestErrorQueries(t *testing.T) {
	ParseQueryErrorTest(t, map[string]any{"age": map[string]any{"$AA": 30, "$lt": 40}}, "invalid query condition for age $AA, only operators supported")
	ParseQueryErrorTest(t, map[string]any{"age": []map[string]any{{"$AA": 30, "$lt": 40}}}, "invalid condition for age, list supported for logical operators only, got")
	ParseQueryErrorTest(t, map[string]any{"$or": map[string]any{"$gt": 30, "$lt": 40}}, "invalid condition for $or, expected list, got: map")
	ParseQueryErrorTest(t, map[string]any{"$or": map[any]any{"$gt": 30, "$lt": 40}}, "invalid query condition for $or, only map of strings supported: ma")
	ParseQueryErrorTest(t, map[string]any{"$or": []int{40}}, "invalid condition for $or, expected list of maps, go")
	ParseQueryErrorTest(t, map[string]any{"$eq": []int{40}}, "operator $eq supported for field conditions only")
	ParseQueryErrorTest(t, map[string]any{"age": map[string]any{"abc": 30, "$lt": 40}}, "invalid query condition for age abc, only operators supported: 30")
	ParseQueryErrorTest(t, map[string]any{"age": map[string]any{"$or": 30, "$lt": 40}}, "invalid query condition for age $or, only operators supported: 30")
	ParseQueryErrorTest(t, map[string]any{"age": 30, "$or": []map[string]any{{"city": map[string]any{"a": 1}}, {"state": "California"}}}, "invalid query condition for city a, only operators supported: ")
	ParseQueryErrorTest(t, map[string]any{"age": 30, "$or": []map[string]any{{"city": []map[string]any{{"a": 1}}}, {"state": "California"}}}, "invalid condition for city, list supported for logical operators only, got: []map[string")
	ParseQueryErrorTest(t, map[string]any{"$eq": map[string]any{"a": 1}}, "operator $eq supported for field conditions onl")
	ParseQueryErrorTest(t, map[string]any{"age": map[string]any{"$gt": map[string]any{"a": 1}}}, "invalid query condition for age $gt, map not supported: map")
	ParseQueryErrorTest(t, map[string]any{"age": map[string]any{"$or": []map[string]any{{"$gt": 1, "$lt": 10}}}}, "invalid logical condition for age $or, only one key supported: map")
	ParseQueryErrorTest(t, map[string]any{"age": map[string]any{"$or": []map[string]any{{"$AA": 1}}}}, "invalid logical condition for age $AA, only operators supported: 1")
}

func TestMappedQueries(t *testing.T) {
	ParseQueryMapperTest(t, nil, "", nil)
	ParseQueryMapperTest(t, map[string]any{}, "", nil)
	ParseQueryMapperTest(t, map[string]any{"age": 30, "city": "New York", "state": "California"}, "_json ->> 'age' = ? AND _json ->> 'city' = ? AND _json ->> 'state' = ?", []any{30, "New York", "California"})
	ParseQueryMapperTest(t, map[string]any{"_id": 30, "city": "New York", "state": "California", "country": "USA"}, "_id = ? AND _json ->> 'city' = ? AND _json ->> 'country' = ? AND _json ->> 'state' = ?", []any{30, "New York", "USA", "California"})
	ParseQueryMapperTest(t, map[string]any{"age": 30, "$AND": []map[string]any{{"city": "New York"}, {"$OR": []map[string]any{{"state": "California"}, {"country": "USA"}}}, {"city": "New York"}}}, " ( _json ->> 'city' = ? AND  ( _json ->> 'state' = ? OR _json ->> 'country' = ? )  AND _json ->> 'city' = ? )  AND _json ->> 'age' = ?", []any{"New York", "California", "USA", "New York", 30})
	ParseQueryMapperTest(t, map[string]any{"age": map[string]any{"$gt": 30, "$lt": 40}}, "_json ->> 'age' > ? AND _json ->> 'age' < ?", []any{30, 40})
	ParseQueryMapperTest(t, map[string]any{"age": map[string]any{"$lte": 30}}, "_json ->> 'age' <= ?", []any{30})
}

func TestMappedError(t *testing.T) {
	ParseMappedErrorTest(t, map[string]any{"_json": 30}, "querying _json directly is not supporte")
	ParseMappedErrorTest(t, map[string]any{"abc'def": 30}, "field path cannot contain ': abc")
}
