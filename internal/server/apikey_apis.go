// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json/v2"
	"net/http"

	"github.com/openrundev/openrun/internal/types"
)

// HTTP adapters for the API key management operations (openrun apikey)

func (h *Handler) createApiKey(r *http.Request) (any, error) {
	var req types.ApiKeyCreateRequest
	if err := json.UnmarshalRead(r.Body, &req); err != nil {
		return nil, types.CreateRequestError(err.Error(), http.StatusBadRequest)
	}
	if req.User != "" {
		updateTargetInContext(r, req.User, false)
	}
	return h.server.CreateApiKey(r.Context(), &req)
}

func (h *Handler) listApiKeys(r *http.Request) (any, error) {
	all, err := parseBoolArg(r.URL.Query().Get("all"), false)
	if err != nil {
		return nil, err
	}
	return h.server.ListApiKeys(r.Context(), all)
}

func (h *Handler) deleteApiKey(r *http.Request) (any, error) {
	id := r.URL.Query().Get("id")
	if id == "" {
		return nil, types.CreateRequestError("id is required", http.StatusBadRequest)
	}
	updateTargetInContext(r, id, false)
	return h.server.DeleteApiKey(r.Context(), id)
}
