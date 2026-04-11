// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import "github.com/gorilla/sessions"

func sessionValueString(session *sessions.Session, key string) (string, bool) {
	if session == nil {
		return "", false
	}
	return mapValueString(session.Values, key)
}

func mapValueString(values map[any]any, key string) (string, bool) {
	raw, ok := values[key]
	if !ok {
		return "", false
	}
	value, ok := raw.(string)
	if !ok {
		return "", false
	}
	return value, true
}

func stateValueString(stateMap map[string]any, key string) (string, bool) {
	raw, ok := stateMap[key]
	if !ok {
		return "", false
	}
	value, ok := raw.(string)
	if !ok {
		return "", false
	}
	return value, true
}

func stateValueBool(stateMap map[string]any, key string) (bool, bool) {
	raw, ok := stateMap[key]
	if !ok {
		return false, false
	}
	value, ok := raw.(bool)
	if !ok {
		return false, false
	}
	return value, true
}

func stateValueStringSlice(stateMap map[string]any, key string) ([]string, bool) {
	raw, ok := stateMap[key]
	if !ok {
		return nil, false
	}
	return anyToStringSlice(raw)
}

func anyToStringSlice(raw any) ([]string, bool) {
	switch values := raw.(type) {
	case []string:
		return append([]string(nil), values...), true
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			item, ok := value.(string)
			if !ok {
				return nil, false
			}
			result = append(result, item)
		}
		return result, true
	default:
		return nil, false
	}
}
