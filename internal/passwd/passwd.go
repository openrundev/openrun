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

func GenerateSessionNonce() (string, string, error) {
	buf1 := make([]byte, 24)
	if _, err := rand.Read(buf1); err != nil {
		return "", "", err
	}
	buf2 := make([]byte, 32)
	if _, err := rand.Read(buf2); err != nil {
		return "", "", err
	}
	return base64.URLEncoding.EncodeToString(buf1), base64.URLEncoding.EncodeToString(buf2), nil
}

// GeneratePassword generates a random password
func GeneratePassword() (string, error) {
	return generateRandString(16, PASSWORD_CHARS)
}
