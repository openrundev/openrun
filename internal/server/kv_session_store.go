// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/base32"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/openrundev/openrun/internal/types"
)

const (
	kvSessionIDBytes        = 32
	maxKVSessionValueLength = 10 << 20 // 10MB
)

var kvSessionIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// KVSessionStore keeps session payloads server-side and puts only an opaque,
// signed session id in the browser cookie.
type KVSessionStore struct {
	Codecs      []securecookie.Codec
	valueCodecs []securecookie.Codec
	Options     *sessions.Options
	db          KVStore
}

var _ sessions.Store = (*KVSessionStore)(nil)

func NewKVSessionStore(db KVStore, keyPairs ...[]byte) *KVSessionStore {
	store := &KVSessionStore{
		Codecs:      securecookie.CodecsFromPairs(keyPairs...),
		valueCodecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:     "/",
			MaxAge:   86400 * 30,
			SameSite: http.SameSiteLaxMode,
			Secure:   false,
		},
		db: db,
	}
	for _, codec := range store.valueCodecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			// Server-side values can exceed cookie limits, but should still be bounded.
			sc.MaxLength(maxKVSessionValueLength)
		}
	}
	store.MaxAge(store.Options.MaxAge)
	return store
}

func (s *KVSessionStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

func (s *KVSessionStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true

	c, errCookie := r.Cookie(name)
	if errCookie != nil {
		return session, nil
	}

	if err := securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...); err != nil {
		return session, err
	}
	if session.ID == "" {
		return session, fmt.Errorf("empty session id for %s", name)
	}
	if err := s.load(r, session); err != nil {
		return session, err
	}
	session.IsNew = false
	return session, nil
}

func (s *KVSessionStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	if s.db == nil {
		return fmt.Errorf("kv session store has no database")
	}
	if session.Options.MaxAge < 0 {
		if session.ID != "" {
			if err := s.db.DeleteKV(r.Context(), s.kvKey(session)); err != nil {
				return err
			}
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	if session.ID == "" {
		randomID := securecookie.GenerateRandomKey(kvSessionIDBytes)
		if len(randomID) != kvSessionIDBytes {
			return fmt.Errorf("error generating session id")
		}
		session.ID = kvSessionIDEncoding.EncodeToString(randomID)
	}

	if err := s.save(r, session); err != nil {
		return err
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, s.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	session.IsNew = false
	return nil
}

func (s *KVSessionStore) MaxAge(age int) {
	s.Options.MaxAge = age
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
	for _, codec := range s.valueCodecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

func (s *KVSessionStore) load(r *http.Request, session *sessions.Session) error {
	if s.db == nil {
		return fmt.Errorf("kv session store has no database")
	}
	value, err := s.db.FetchKVBlob(r.Context(), s.kvKey(session))
	if err != nil {
		return err
	}
	return securecookie.DecodeMulti(session.Name(), string(value), &session.Values, s.valueCodecs...)
}

func (s *KVSessionStore) save(r *http.Request, session *sessions.Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, s.valueCodecs...)
	if err != nil {
		return err
	}

	var expireAt *time.Time
	if session.Options.MaxAge > 0 {
		t := time.Now().UTC().Add(time.Duration(session.Options.MaxAge) * time.Second)
		expireAt = &t
	}

	if err := s.db.UpsertKVBlob(r.Context(), s.kvKey(session), []byte(encoded), expireAt); err != nil {
		return fmt.Errorf("error storing session: %w", err)
	}
	return nil
}

func (s *KVSessionStore) kvKey(session *sessions.Session) string {
	return types.HTTP_SESSION_KV_PREFIX + session.Name() + ":" + session.ID
}
