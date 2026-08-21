// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package store

import "time"

const (
	ID_FIELD         = "_id"
	VERSION_FIELD    = "_version"
	CREATED_BY_FIELD = "_created_by"
	UPDATED_BY_FIELD = "_updated_by"
	CREATED_AT_FIELD = "_created_at"
	UPDATED_AT_FIELD = "_updated_at"
	JSON_FIELD       = "_json"
)

var RESERVED_FIELDS = map[string]bool{
	ID_FIELD:         true,
	VERSION_FIELD:    true,
	CREATED_BY_FIELD: true,
	UPDATED_BY_FIELD: true,
	CREATED_AT_FIELD: true,
	UPDATED_AT_FIELD: true,
	JSON_FIELD:       true,
}

type EntryId int64
type UserId string
type Document map[string]any

type Entry struct {
	Id        EntryId
	Version   int64
	CreatedBy UserId
	UpdatedBy UserId
	CreatedAt time.Time
	UpdatedAt time.Time
	Data      Document
}
