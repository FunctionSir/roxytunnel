/*
 * @Author: FunctionSir
 * @License: AGPLv3
 * @Date: 2025-09-23 18:18:02
 * @LastEditTime: 2025-09-27 23:40:00
 * @LastEditors: FunctionSir
 * @Description: -
 * @FilePath: /roxytunnel/core/shared/tls.go
 */
package shared

import (
	"bytes"
	"context"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/ocsp"
)

// TLS verify modes
const (
	TLSVerifyModeStrict   string = "strict"   // Full + OCSP
	TLSVerifyModeFull     string = "full"     // Pinned + regular verification
	TLSVerifyModePinned   string = "pinned"   // Only match cert pinning, can NOT be used with TLSCertPinningModeOff
	TLSVerifyModeDisabled string = "disabled" // Disable all TLS cert verification (INSECURE! FOR TESTING ONLY!)
)

// TLS cert pinning modes
const (
	TLSCertPinningModePubKey string = "pubkey" // Pinning the cert by the SHA-512 of public key, more convenient
	TLSCertPinningModeCert   string = "cert"   // Pinning the cert by the SHA-512 of the whole cert, more secure
	TLSCertPinningModeOff    string = "off"    // Do not use cert pinning, vulnerable if any trust CA is compromised, and can NOT be used with TLSVerifyModePinned
)

// TLS client meek modes
const (
	TLSClientMeekFirefox          string = "firefox"            // Let TLS handshakes look like Firefox
	TLSClientMeekChrome           string = "chrome"             // Let TLS handshakes look like Chrome
	TLSClientMeekEdge             string = "edge"               // Let TLS handshakes look like Edge
	TLSClientMeekSafari           string = "safari"             // Let TLS handshakes look like Safari on Mac systems
	TLSClientMeekAndroid11OkHttp  string = "android_11_okhttp"  // Let TLS handshakes look like the OkHttp library on Android 11
	TLSClientMeekIOS              string = "ios"                // Let TLS handshakes look like Safari on IOS systems
	TLSClientMeekQQ               string = "qq"                 // Let TLS handshakes look like QQ Browser
	TLSClientMeek360              string = "360"                // Let TLS handshakes look like 360 Browser
	TLSClientMeekRandomized       string = "randomized"         // Let TLS handshakes use a randomized client hello schema, maybe with or with no ALPN
	TLSClientMeekRandomizedALPN   string = "randomized_alpn"    // Let TLS handshakes use a randomized client hello schema with ALPN
	TLSClientMeekRandomizedNoALPN string = "randomized_no_alpn" // Let TLS handshakes use a randomized client hello schema with no ALPN
	TLSClientMeekGolang           string = "golang"             // Let TLS handshakes look like a regular Golang based program using standard library, functionally equals to no meek
)

// Pre-defined errors
var (
	ErrInvalidTLSVerifyMode                 error = errors.New("invalid TLS verify mode")
	ErrInvalidTLSCertPinningMode            error = errors.New("invalid TLS cert pinning mode")
	ErrVerifyModeSetToPinnedButNoCertPinned error = errors.New("cert verify mode set to pinned but no cert pinned")
	ErrOCSPVerificationFailed               error = errors.New("cert OCSP verification failed")
	ErrCertPinMismatch                      error = errors.New("TLS cert pin mismatch")
	ErrInvalidTLSMeekTarget                 error = errors.New("invalid TLS meek target")
)

// OCSP content-type
const (
	ContentTypeOCSPRequest string = "application/ocsp-request"
)

type TLSCertVerificationFunc func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
type HTTPSDialTLSCtxFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func ListOfCertVerifiers(verifiers []TLSCertVerificationFunc) TLSCertVerificationFunc {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		for _, verifier := range verifiers {
			if verifier == nil {
				continue
			}
			err := verifier(rawCerts, verifiedChains)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

// Verify TLS cert using OCSP verifier
func CertOCSPVerifier(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) <= 1 {
		return ErrOCSPVerificationFailed
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	issuer, err := x509.ParseCertificate(rawCerts[1])
	if err != nil {
		return err
	}
	req, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return err
	}
	if len(leaf.OCSPServer) <= 0 {
		return ErrOCSPVerificationFailed
	}
	resp, err := http.Post(leaf.OCSPServer[0], ContentTypeOCSPRequest, bytes.NewReader(req))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	ocspResp, err := ocsp.ParseResponse(respBody, issuer)
	if err != nil {
		return err
	}
	if ocspResp.Status != ocsp.Good {
		return ErrOCSPVerificationFailed
	}
	return nil
}

func CertPinningVerifier(pinningMode string, pinned string) (TLSCertVerificationFunc, error) {
	switch pinningMode {
	case TLSCertPinningModeOff:
		return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil
		}, nil
	case TLSCertPinningModePubKey, TLSCertPinningModeCert:
		return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) <= 0 {
				return ErrCertPinMismatch
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			var bytesToHash []byte
			if pinningMode == TLSCertPinningModePubKey {
				bytesToHash, err = x509.MarshalPKIXPublicKey(cert.PublicKey)
				if err != nil {
					return err
				}
			} else {
				bytesToHash = cert.Raw
			}
			chksum := sha512.Sum512(bytesToHash)
			if pinned != hex.EncodeToString(chksum[:]) {
				return ErrCertPinMismatch
			}
			return nil
		}, nil
	default:
		return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return ErrInvalidTLSCertPinningMode
		}, ErrInvalidTLSCertPinningMode
	}
}

func NewRoxyCertVerificationFunc(mode string, pinningMode string, pinned string) (TLSCertVerificationFunc, error) {
	verifyFuncs := make([]TLSCertVerificationFunc, 0)
	switch mode {
	case TLSVerifyModeStrict:
		verifyFuncs = append(verifyFuncs, CertOCSPVerifier)
		fallthrough
	case TLSVerifyModeFull, TLSVerifyModePinned:
		if mode == TLSVerifyModePinned && pinningMode == TLSCertPinningModeOff {
			return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				return ErrVerifyModeSetToPinnedButNoCertPinned
			}, ErrVerifyModeSetToPinnedButNoCertPinned
		}
		verifier, err := CertPinningVerifier(pinningMode, pinned)
		if err != nil {
			return verifier, err
		}
		verifyFuncs = append(verifyFuncs, verifier)
		return ListOfCertVerifiers(verifyFuncs), nil
	case TLSVerifyModeDisabled:
		return nil, nil
	default:
		return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error { return ErrInvalidTLSVerifyMode }, ErrInvalidTLSVerifyMode
	}
}

func NewMeekedHTTPSDialTLSCtxFunc(meekMode string, utlsConf *utls.Config) (HTTPSDialTLSCtxFunc, error) {
	// Determine uTLS client hello ID.
	var utlsClientHelloID utls.ClientHelloID
	switch meekMode {
	case TLSClientMeekFirefox:
		utlsClientHelloID = utls.HelloFirefox_Auto
	case TLSClientMeekChrome:
		utlsClientHelloID = utls.HelloChrome_Auto
	case TLSClientMeekEdge:
		utlsClientHelloID = utls.HelloEdge_Auto
	case TLSClientMeekSafari:
		utlsClientHelloID = utls.HelloSafari_Auto
	case TLSClientMeekAndroid11OkHttp:
		utlsClientHelloID = utls.HelloAndroid_11_OkHttp
	case TLSClientMeekIOS:
		utlsClientHelloID = utls.HelloIOS_Auto
	case TLSClientMeekQQ:
		utlsClientHelloID = utls.HelloQQ_Auto
	case TLSClientMeek360:
		utlsClientHelloID = utls.Hello360_Auto
	case TLSClientMeekRandomized:
		utlsClientHelloID = utls.HelloRandomized
	case TLSClientMeekRandomizedALPN:
		utlsClientHelloID = utls.HelloRandomizedALPN
	case TLSClientMeekRandomizedNoALPN:
		utlsClientHelloID = utls.HelloRandomizedNoALPN
	case TLSClientMeekGolang:
		utlsClientHelloID = utls.HelloGolang
	default:
		return nil, ErrInvalidTLSMeekTarget
	}

	// Construct HTTPSDialTLSCtxFunc.
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{}
		tcpConn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		utlsConfClone := utlsConf.Clone()
		utlsConn := utls.UClient(tcpConn, utlsConfClone, utlsClientHelloID)
		if err := utlsConn.Handshake(); err != nil {
			return nil, err
		}
		return utlsConn, nil
	}, nil
}
