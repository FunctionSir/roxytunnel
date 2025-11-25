/*
 * @Author: FunctionSir
 * @License: AGPLv3
 * @Date: 2025-09-21 18:58:29
 * @LastEditTime: 2025-11-24 21:17:51
 * @LastEditors: FunctionSir
 * @Description: -
 * @FilePath: /roxytunnel/core/shared/auth.go
 */

package shared

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
)

type RoxyAuthMethod string

// Supported auth methods
const (
	AuthMethodBearer RoxyAuthMethod = "bearer" // For Bearer auth
	// TODO: Support more auth method
)

// Related HTTP headers
const HTTPHeaderAuthorization string = "Authorization"

// Related errors
var (
	ErrAuthMethodNotSupported error = errors.New("auth method not supported")
	ErrInvalidBearerToken     error = errors.New("invalid bearer token")
)

// Bearer checker regex, based on RFC 6750
//
// Ref: https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1
var BearerCheckerRegex *regexp.Regexp = regexp.MustCompile("^[A-Za-z0-9._~+/-]+=*$")

func CheckBearerToken(token string) error {
	if !BearerCheckerRegex.MatchString(token) {
		return ErrInvalidBearerToken
	}
	return nil
}

func SetBearerAuth(r *http.Request, token string) error {
	err := CheckBearerToken(token)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	return nil
}

// Official Roxy Protocol recommends you to use at least 30 bytes (240 bits) of randomness.
//
// The official implement uses 48 bytes (384 bits) of randomness.
func GenBearerToken() string {
	buf := make([]byte, 48)
	_, _ = rand.Read(buf) // According to Go official, it "never returns an error, and always fills b entirely".
	return base64.RawURLEncoding.EncodeToString(buf)
}

func NewHeaderWithBearer(token string) (http.Header, error) {
	err := CheckBearerToken(token)
	if err != nil {
		return nil, err
	}
	newHeader := make(http.Header)
	newHeader.Set(HTTPHeaderAuthorization, fmt.Sprintf("Bearer %s", token))
	return newHeader, nil
}
