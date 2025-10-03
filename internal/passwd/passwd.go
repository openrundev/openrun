// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package passwd

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

const (
	PASSWORD_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#%^&*()_-+=<>?/|"
	BCRYPT_COST    = 10
)

// GenerateRandomPassword generates a random password
func generateRandString(length int, charsAllowed string) (string, error) {
	charsetLength := len(charsAllowed)
	password := make([]byte, length)

	for i := 0; i < length; i++ {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(charsetLength)))
		if err != nil {
			return "", err
		}
		password[i] = charsAllowed[randomIndex.Int64()]
	}

	return string(password), nil
}

// GeneratePassword generates a random password
func GeneratePassword() (string, error) {
	return generateRandString(16, PASSWORD_CHARS)
}

func GenerateSessionNonce() (string, string, error) {
	session, err := GenerateRandomKey(24)
	if err != nil {
		return "", "", err
	}
	nonce, err := GenerateRandomKey(32)
	if err != nil {
		return "", "", err
	}
	return base64.URLEncoding.EncodeToString(session), base64.URLEncoding.EncodeToString(nonce), nil
}

func GenerateRandomKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}
