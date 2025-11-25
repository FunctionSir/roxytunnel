/*
 * @Author: FunctionSir
 * @License: AGPLv3
 * @Date: 2025-09-21 10:58:22
 * @LastEditTime: 2025-11-25 23:15:15
 * @LastEditors: FunctionSir
 * @Description: -
 * @FilePath: /roxytunnel/core/client/client.go
 */

package client

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha512"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"

	"github.com/FunctionSir/roxytunnel/core/shared"
	"github.com/coder/websocket"
	"github.com/flynn/noise"
	utls "github.com/refraction-networking/utls"
	"github.com/songgao/water"
	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"github.com/tink-crypto/tink-go/v2/tink"
	_ "modernc.org/sqlite"
)

// Related HTTP headers
const (
	HTTPHeaderXPadding   string = "X-Padding"
	HTTPHeaderXNoiseInit string = "X-Noise-Init"
	HTTPHeaderXNoiseResp string = "X-Noise-Resp"
)

// HKDF related
const (
	HKDFInfoClientToServerAESGCMSIV string = "HKDF_INFO_CLIENT_TO_SERVER_AES_GCM_SIV"
	HKDFInfoServerToClientAESGCMSIV string = "HKDF_INFO_SERVER_TO_CLIENT_AES_GCM_SIV"
)

// AES related
const (
	AESGCMSIVKeyLenAsBytes int = 32
)

// Salt config
const (
	ClientSideSessionSaltLen int = 16
)

// Key rotation
const (
	KeyRotationInterval uint64 = 1 << 31 // = 2^31
)

// Errors
var (
	ErrInvalidPaddingLengthConfig    error = errors.New("invalid padding length config")
	ErrUnexpectedNoiseIKCipherStates error = errors.New("unexpected Noise IK cipher states")
	ErrEmptyNoiseResponse            error = errors.New("empty noise response")
	ErrTAPNotClosedProperlyBefore    error = errors.New("TAP not closed properly before")
)

// Struct RoxyClient is the struct of Roxy Client
//
// Instance DB is a SQLite database contains everything needs, like config.
//
// Logs are logged to this DB too, so it's easy to move everything to another machine without any pain.
//
// You don't need to close any chan manually.
type RoxyClient struct {
	instanceDB                        string
	dbConn                            *sql.DB
	sessionSalt                       []byte
	clientToServerKey                 []byte
	serverToClientKey                 []byte
	clientToServerAEAD                tink.AEAD
	serverToClientAEAD                tink.AEAD
	conn                              *websocket.Conn
	wssReadChan                       <-chan []byte
	wssWriteChan                      chan<- []byte
	wssReadErrChan                    <-chan error
	wssWriteErrChan                   <-chan error
	tap                               *water.Interface
	tapReadChan                       <-chan []byte
	tapWriteChan                      chan<- []byte
	tapReadErrChan                    <-chan error
	tapWriteErrChan                   <-chan error
	tapToWSSForwarderErrChan          <-chan error
	wssToTAPForwarderErrChan          <-chan error
	serverToClientAntiReplayChecker   *shared.AntiReplayChecker
	clientToServerAntiReplayGenerator *shared.AntiReplayGenerator
	linkCtx                           context.Context
	logCtx                            context.Context
	linkCancel                        context.CancelFunc
	logCancel                         context.CancelFunc
	pipelineWG                        sync.WaitGroup
	disconnectOnce                    sync.Once
}

func (client *RoxyClient) LogToScreen(level shared.LogLevel, msg string) {
	shared.LogToScreen(level, msg)
}

func (client *RoxyClient) LogToDatabase(level shared.LogLevel, msg string) {
	shared.LogToDatabase(client.logCtx, client.dbConn, level, msg)
}

func (client *RoxyClient) LogToAll(level shared.LogLevel, msg string) {
	client.LogToScreen(level, msg)
	client.LogToDatabase(level, msg)
}

func SerializedWSSReader(ctx context.Context, conn *websocket.Conn, wg *sync.WaitGroup) (<-chan []byte, <-chan error) {
	dataChan := make(chan []byte)
	errChan := make(chan error, 1)
	wg.Go(func() {
		defer close(dataChan)
		defer close(errChan)
		for {
			_, payload, err := conn.Read(ctx)
			if err != nil {
				errChan <- err
				return
			}
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			case dataChan <- payload:
				// Just do nothing.
			}
		}
	})
	return dataChan, errChan
}

// Althought it has a "closed chan check", you should not close the Chan manually.
//
// Just use context and let GC do the extra works.
func SerializedWSSWriter(ctx context.Context, conn *websocket.Conn, wg *sync.WaitGroup) (chan<- []byte, <-chan error) {
	dataChan := make(chan []byte)
	errChan := make(chan error, 1)
	wg.Go(func() {
		defer close(errChan)
		for {
			var payload []byte
			var ok bool
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			case payload, ok = <-dataChan:
				if !ok {
					return
				}
				err := conn.Write(ctx, websocket.MessageBinary, payload)
				if err != nil {
					errChan <- err
					return
				}
			}
		}
	})
	return dataChan, errChan
}

func SerializedTAPReader(ctx context.Context, tap *water.Interface, wg *sync.WaitGroup) (<-chan []byte, <-chan error) {
	dataChan := make(chan []byte)
	errChan := make(chan error, 1)
	wg.Go(func() {
		defer close(dataChan)
		defer close(errChan)
		for {
			buf := make([]byte, 65536)
			n, err := tap.Read(buf)
			if err != nil {
				errChan <- err
				return
			}
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			case dataChan <- buf[:n]:
				// Just do nothing.
			}
		}
	})
	return dataChan, errChan
}

// Although it has a "closed chan check", you should not close the Chan manually.
//
// Just use context and let GC do the extra works.
func SerializedTAPWriter(ctx context.Context, tap *water.Interface, wg *sync.WaitGroup) (chan<- []byte, <-chan error) {
	dataChan := make(chan []byte)
	errChan := make(chan error, 1)
	wg.Go(func() {
		defer close(errChan)
		for {
			var payload []byte
			var ok bool
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			case payload, ok = <-dataChan:
				if !ok {
					return
				}
				if _, err := tap.Write(payload); err != nil {
					errChan <- err
					return
				}
			}
		}
	})
	return dataChan, errChan
}

func (client *RoxyClient) tapToWSSForwarder() <-chan error {
	errChan := make(chan error, 1)
	client.pipelineWG.Go(func() {
		defer close(errChan)
		for {
			select {
			case <-client.linkCtx.Done():
				return
			case data, ok := <-client.tapReadChan:
				if !ok {
					return
				}
				dataWithARH, rotationNeeded, err := client.clientToServerAntiReplayGenerator.NextAttachToData(data)
				if err != nil {
					errChan <- err
					return
				}
				encData, err := client.clientToServerAEAD.Encrypt(dataWithARH, client.sessionSalt)
				if err != nil {
					errChan <- err
					return
				}
				if rotationNeeded {
					aesC2SKey, err := hkdf.Key(sha512.New, client.clientToServerKey, client.sessionSalt, HKDFInfoClientToServerAESGCMSIV, AESGCMSIVKeyLenAsBytes)
					if err != nil {
						errChan <- err
						return
					}
					client.clientToServerKey = aesC2SKey
					newAEAD, err := subtle.NewAESGCMSIV(aesC2SKey)
					if err != nil {
						errChan <- err
						return
					}
					client.clientToServerAEAD = newAEAD
				}
				// Send data.
				client.wssWriteChan <- encData
			}
		}
	})
	return errChan
}

func (client *RoxyClient) wssToTAPForwarder() <-chan error {
	errChan := make(chan error, 1)
	client.pipelineWG.Go(func() {
		defer close(errChan)
		for {
			select {
			case <-client.linkCtx.Done():
				return
			case data, ok := <-client.wssReadChan:
				if !ok {
					return
				}
				plaintextData, err := client.serverToClientAEAD.Decrypt(data, client.sessionSalt)
				if err != nil {
					errChan <- err
					return
				}
				payload, ok, rotationNeeded := client.serverToClientAntiReplayChecker.CheckData(plaintextData)
				if !ok {
					continue
				}
				if rotationNeeded {
					aesS2CKey, err := hkdf.Key(sha512.New, client.serverToClientKey, client.sessionSalt, HKDFInfoServerToClientAESGCMSIV, AESGCMSIVKeyLenAsBytes)
					if err != nil {
						errChan <- err
						return
					}
					client.serverToClientKey = aesS2CKey
					newAEAD, err := subtle.NewAESGCMSIV(aesS2CKey)
					if err != nil {
						errChan <- err
						return
					}
					client.serverToClientAEAD = newAEAD
				}
				// Send data.
				client.tapWriteChan <- payload
			}
		}
	})
	return errChan
}

// Do NOT start watchdog with client.linkWorkersWG.Go()!
func (client *RoxyClient) Watchdog() {
	var err error
	select {
	case <-client.linkCtx.Done():
		return
	case err = <-client.wssReadErrChan:
		_ = client.Disconnect()
		client.LogToAll(shared.LogLevelError,
			"Watchdog noticed a error of: "+err.Error()+
				" while monitoring WSS read error channel, attempted disconnect.")
	case err = <-client.wssWriteErrChan:
		_ = client.Disconnect()
		client.LogToAll(shared.LogLevelError,
			"Watchdog noticed a error of: "+err.Error()+
				" while monitoring WSS write error channel, attempted disconnect.")
	case err = <-client.tapReadErrChan:
		_ = client.Disconnect()
		client.LogToAll(shared.LogLevelError,
			"Watchdog noticed a error of: "+err.Error()+
				" while monitoring TAP read error channel, attempted disconnect.")
	case err = <-client.tapWriteErrChan:
		_ = client.Disconnect()
		client.LogToAll(shared.LogLevelError,
			"Watchdog noticed a error of: "+err.Error()+
				" while monitoring TAP write error channel, attempted disconnect.")
	}
}

// Create a new roxy client instance from a specified instance DB.
func NewRoxyClient(instanceDB string) (*RoxyClient, error) {
	// Connect to instance DB.
	db, err := sql.Open("sqlite", instanceDB)
	if err != nil {
		return &RoxyClient{instanceDB: instanceDB}, err
	}

	// Create Griseo RH structs.
	antiReplayChecker, err := shared.NewAntiReplayChecker(KeyRotationInterval)
	if err != nil {
		return &RoxyClient{instanceDB: instanceDB}, err
	}
	antiReplayGen, err := shared.NewAntiReplayGenerator(KeyRotationInterval)
	if err != nil {
		return &RoxyClient{instanceDB: instanceDB}, err
	}

	// TODO: Add checking of DB type (should be "client").

	// Create log context for client.
	logCtxWithCancel, logCtxCancel := context.WithCancel(context.Background())

	// Construct and return the client instance.
	return &RoxyClient{
		instanceDB:                        instanceDB,
		dbConn:                            db,
		logCtx:                            logCtxWithCancel,
		logCancel:                         logCtxCancel,
		serverToClientAntiReplayChecker:   antiReplayChecker,
		clientToServerAntiReplayGenerator: antiReplayGen,
	}, nil
}

// TODO: Use Noise IK message to auth.
// TODO: Support pluggable auth.
// FIXME: Remove Bearer Auth Related.
func (client *RoxyClient) Connect() error {
	// Create link context for this connection.
	client.linkCtx, client.linkCancel = context.WithCancel(context.Background())

	// Set disconnect once.
	client.disconnectOnce = sync.Once{}

	// // Get auth method.
	// var authMethod, authPayload string
	// err := shared.GetConfVal(client.linkCtx, client.dbConn, shared.ConfKeyClientAuthMethod, &authMethod)
	// if err != nil {
	// 	return err
	// }

	// // Check if auth method is supported or not.
	// if shared.RoxyAuthMethod(authMethod) != shared.AuthMethodBearer { // Currently, AuthMethodBearer is the only supported one
	// 	return shared.ErrAuthMethodNotSupported
	// }

	// // Get auth payload.
	// err = shared.GetConfVal(client.linkCtx, client.dbConn, shared.ConfKeyClientAuthPayload, &authPayload)
	// if err != nil {
	// 	return err
	// }

	// Get anti-replay related values from Memo.
	var curNextEpoch uint32
	var curNextSeq uint64
	// TODO: Finish memo keys.
	err := shared.GetMemoVal(client.linkCtx, client.dbConn, "", &curNextEpoch)
	if err != nil {
		return err
	}
	// TODO: Finish memo keys.
	err = shared.GetMemoVal(client.linkCtx, client.dbConn, "", &curNextSeq)
	if err != nil {
		return err
	}

	// Get header length random padding config.
	var headersLenRandPadMin, headersLenRandPadMax int
	err = shared.GetConfVal(client.linkCtx, client.dbConn, shared.ConfKeyClientHeadersLengthRandomPaddingMax, &headersLenRandPadMax)
	if err != nil {
		return err
	}
	var paddingStr string
	if headersLenRandPadMax > 0 {
		err = shared.GetConfVal(client.linkCtx, client.dbConn, shared.ConfKeyClientHeadersLengthRandomPaddingMin, &headersLenRandPadMin)
		if err != nil {
			return err
		}
		if headersLenRandPadMax < headersLenRandPadMin {
			return ErrInvalidPaddingLengthConfig
		}
		padLenOffset, err := rand.Int(rand.Reader, big.NewInt(int64(headersLenRandPadMax-headersLenRandPadMin+1)))
		if err != nil {
			return err
		}
		if !padLenOffset.IsInt64() {
			return ErrInvalidPaddingLengthConfig
		}
		padLenInt64 := padLenOffset.Int64() + int64(headersLenRandPadMin)
		paddingData := make([]byte, padLenInt64)
		_, _ = rand.Read(paddingData) // According to Go official, it "never returns an error, and always fills b entirely".
		paddingStr = base64.RawURLEncoding.EncodeToString(paddingData)
	}

	// Get Base64 encoded Noise keys.
	var base64ClientPubKey, base64ClientPrivKey, base64ServerPubKey, base64PSK string
	err = shared.GetConfVal(client.linkCtx, client.dbConn, shared.ConfKeyClientNoiseClientPublicKey, &base64ClientPubKey)
	if err != nil {
		return err
	}
	err = shared.GetConfVal(client.linkCtx, client.dbConn, shared.ConfKeyClientNoiseClientPrivateKey, &base64ClientPrivKey)
	if err != nil {
		return err
	}
	err = shared.GetConfVal(client.linkCtx, client.dbConn, shared.ConfKeyClientNoiseServerPublicKey, &base64ServerPubKey)
	if err != nil {
		return err
	}
	err = shared.GetConfVal(client.linkCtx, client.dbConn, shared.ConfKeyClientNoisePSK, &base64PSK)
	if err != nil {
		return err
	}

	// Decode Base64 Noise keys.
	var clientNoisePubKey, clientNoisePrivKey, serverNoisePubKey, noisePSK []byte
	clientNoisePubKey, err = base64.RawURLEncoding.DecodeString(base64ClientPubKey)
	if err != nil {
		return err
	}
	clientNoisePrivKey, err = base64.RawURLEncoding.DecodeString(base64ClientPrivKey)
	if err != nil {
		return err
	}
	serverNoisePubKey, err = base64.RawURLEncoding.DecodeString(base64ServerPubKey)
	if err != nil {
		return err
	}
	noisePSK, err = base64.RawURLEncoding.DecodeString(base64PSK)
	if err != nil {
		return err
	}

	// Construct client Noise key pair.
	clientNoiseKeyPair := noise.DHKey{
		Private: clientNoisePrivKey,
		Public:  clientNoisePubKey,
	}

	// Construct Noise config and handshake state.
	noiseConf := noise.Config{
		CipherSuite: noise.NewCipherSuite(
			noise.DH25519,
			noise.CipherChaChaPoly,
			noise.HashSHA512,
		),
		Pattern:               noise.HandshakeIK,
		Initiator:             true,
		StaticKeypair:         clientNoiseKeyPair,
		PeerStatic:            serverNoisePubKey,
		Random:                rand.Reader,
		PresharedKey:          noisePSK,
		PresharedKeyPlacement: 2, // Use psk2 to get a better forward security performance.
	}
	hs, err := noise.NewHandshakeState(noiseConf)
	if err != nil {
		return err
	}

	// Gen client side session salt.
	clientSideSessionSalt := make([]byte, ClientSideSessionSaltLen)
	_, _ = rand.Read(clientSideSessionSalt) // As Go official said, it's safe to not check the n or err val.

	// Construct Noise IK init and encode it.
	noiseIKInit, csC2S, csS2C, err := hs.WriteMessage(nil, clientSideSessionSalt) // Payload is client side session salt
	if err != nil {
		return err
	}
	if csC2S != nil || csS2C != nil {
		return ErrUnexpectedNoiseIKCipherStates
	}
	base64NoiseIKInit := base64.RawURLEncoding.EncodeToString(noiseIKInit)

	// Construct HTTP header.
	header := make(http.Header)
	header.Add(HTTPHeaderXNoiseInit, base64NoiseIKInit)
	if headersLenRandPadMax > 0 {
		header.Add(HTTPHeaderXPadding, paddingStr)
	}

	// Get TLS cert verification config.
	var certVerifyMode string
	err = shared.GetConfVal(client.linkCtx, client.dbConn, shared.ConfKeyClientTLSVerifyMode, &certVerifyMode)
	if err != nil {
		return err
	}
	var tlsConfInsecureSkipVerify bool
	switch certVerifyMode {
	case shared.TLSVerifyModePinned, shared.TLSVerifyModeDisabled:
		tlsConfInsecureSkipVerify = true
	case shared.TLSVerifyModeStrict, shared.TLSVerifyModeFull:
		tlsConfInsecureSkipVerify = false
	default:
		return shared.ErrInvalidTLSVerifyMode
	}

	// Get cert pinning mode.
	var certPinning string
	err = shared.GetConfVal(client.linkCtx, client.dbConn, shared.ConfKeyClientTLSCertPinning, &certPinning)
	if err != nil {
		return err
	}

	// Get pinned cert.
	var certPinned string
	if certPinning != shared.TLSCertPinningModeOff {
		err = shared.GetConfVal(client.linkCtx, client.dbConn, shared.ConfKeyClientTLSCertPinned, &certPinned)
		if err != nil {
			return err
		}
	}

	// Construct TLS cert verifier.
	verifier, err := shared.NewRoxyCertVerificationFunc(certVerifyMode, certPinning, certPinned)
	if err != nil {
		return err
	}

	// Get TLS server name.
	var serverName string
	err = shared.GetConfVal(client.linkCtx, client.dbConn, shared.ConfKeyClientTLSServerName, &serverName)
	if err != nil {
		return err
	}

	// Construct uTLS client config.
	utlsConfig := &utls.Config{
		InsecureSkipVerify:    tlsConfInsecureSkipVerify,
		VerifyPeerCertificate: verifier,
		ServerName:            serverName,
	}

	// Get TLS meek mode.
	var meekMode string
	err = shared.GetConfVal(client.linkCtx, client.dbConn, shared.ConfKeyClientTLSMeek, &meekMode)
	if err != nil {
		return err
	}

	// Construct HTTPSDialTLSCtxFunc.
	httpsDialTLSCtxFunc, err := shared.NewMeekedHTTPSDialTLSCtxFunc(meekMode, utlsConfig)
	if err != nil {
		return err
	}

	// Construct HTTPS client.
	httpsClient := http.Client{
		Transport: &http.Transport{
			Proxy:          http.ProxyFromEnvironment,
			DialTLSContext: httpsDialTLSCtxFunc,
		},
	}

	// Construct WSS dial options.
	dialOptions := websocket.DialOptions{
		HTTPHeader: header,
		HTTPClient: &httpsClient,
	}

	// Get server to connect to.
	var server string
	err = shared.GetConfVal(client.linkCtx, client.dbConn, shared.ConfKeyClientServer, &server)
	if err != nil {
		return err
	}

	// Dial WebSocket.
	wsConn, resp, err := websocket.Dial(client.linkCtx, server, &dialOptions)
	if err != nil {
		return err
	}

	// Get Noise response from server and decode it.
	base64NoiseResp := resp.Header.Get(HTTPHeaderXNoiseResp)
	noiseResp, err := base64.RawURLEncoding.DecodeString(base64NoiseResp)
	if err != nil {
		return err
	}
	if len(noiseResp) <= 0 {
		return ErrEmptyNoiseResponse
	}

	// Process Noise response.
	serverSideSessionSalt, csC2S, csS2C, err := hs.ReadMessage(nil, noiseResp)
	if err != nil {
		return err
	}
	if csC2S == nil || csS2C == nil {
		return ErrUnexpectedNoiseIKCipherStates
	}

	// Construct whole session salt.
	client.sessionSalt = make([]byte, 0)
	client.sessionSalt = append(client.sessionSalt, clientSideSessionSalt...)
	client.sessionSalt = append(client.sessionSalt, serverSideSessionSalt...)

	// Get Noise send and recv keys.
	aesC2SKeyBeforeHKDF := csC2S.UnsafeKey() // Don't be afraid of "Unsafe", it just used to get key for AES-GCM-SIV.
	aesS2CKeyBeforeHKDF := csS2C.UnsafeKey() // Don't be afraid of "Unsafe", it just used to get key for AES-GCM-SIV.

	// Use HKDF to derive AES client to server key.
	aesC2SKey, err := hkdf.Key(sha512.New, aesC2SKeyBeforeHKDF[:], client.sessionSalt, HKDFInfoClientToServerAESGCMSIV, AESGCMSIVKeyLenAsBytes)
	if err != nil {
		return err
	}
	client.clientToServerKey = aesC2SKey

	// Use HKDF to derive AES server to client key.
	aesS2CKey, err := hkdf.Key(sha512.New, aesS2CKeyBeforeHKDF[:], client.sessionSalt, HKDFInfoServerToClientAESGCMSIV, AESGCMSIVKeyLenAsBytes)
	if err != nil {
		return err
	}
	client.serverToClientKey = aesS2CKey

	// Construct and set Tink AES-GCM-SIV AEADs.
	aesC2SAEAD, err := subtle.NewAESGCMSIV(aesC2SKey)
	if err != nil {
		return err
	}
	client.clientToServerAEAD = aesC2SAEAD
	aesS2CAEAD, err := subtle.NewAESGCMSIV(aesS2CKey)
	if err != nil {
		return err
	}
	client.serverToClientAEAD = aesS2CAEAD

	// Set client.conn.
	client.conn = wsConn

	// Start WSS serialized reader/writer.
	client.wssReadChan, client.wssReadErrChan = SerializedWSSReader(client.linkCtx, client.conn, &client.pipelineWG)
	client.wssWriteChan, client.wssWriteErrChan = SerializedWSSWriter(client.linkCtx, client.conn, &client.pipelineWG)

	// Create TAP interface.
	if client.tap != nil {
		_ = client.Disconnect()
		return ErrTAPNotClosedProperlyBefore
	}

	tapCfg := water.Config{
		DeviceType: water.TAP,
	}
	client.tap, err = water.New(tapCfg)
	if err != nil {
		_ = client.Disconnect()
		return err
	}
	client.LogToAll(shared.LogLevelInfo, fmt.Sprintf("Created TAP device %q.", client.tap.Name()))

	// Start TAP serialized reader/writer.
	client.tapReadChan, client.tapReadErrChan = SerializedTAPReader(client.linkCtx, client.tap, &client.pipelineWG)
	client.tapWriteChan, client.tapWriteErrChan = SerializedTAPWriter(client.linkCtx, client.tap, &client.pipelineWG)

	// Start forwarders.
	client.tapToWSSForwarderErrChan = client.tapToWSSForwarder()
	client.wssToTAPForwarderErrChan = client.wssToTAPForwarder()

	// Start watchdog.
	go client.Watchdog() // Do NOT start watchdog with client.linkWorkersWG.Go()!

	// Nothing bad happened /
	return nil
}

// Get TAP name.
func (client *RoxyClient) IfaceName() string {
	if client.tap == nil {
		return ""
	}
	return client.tap.Name()
}

func (client *RoxyClient) Disconnect() error {
	var errs error
	client.disconnectOnce.Do(func() {
		// Cancel link context to terminate all operations.
		if client.linkCancel != nil {
			client.linkCancel()
		}

		// Wait non-watchdog goroutines finished.
		client.pipelineWG.Wait()

		// Close the WSS connection.
		if client.conn != nil {
			// It's safe to close the WSS conn multi-times, don't panic.
			errs = errors.Join(errs, client.conn.Close(websocket.StatusNormalClosure, "bye"))
			client.conn = nil
		}

		// Close the TAP device.
		if client.tap != nil {
			tapName := client.tap.Name()
			errs = errors.Join(errs, client.tap.Close())
			client.tap = nil
			if errs == nil {
				client.LogToAll(shared.LogLevelInfo, fmt.Sprintf("Closed TAP device %q.", tapName))
			}
		}

		// Set session salt to nil.
		client.sessionSalt = nil

		// Set some vals to nil.
		client.clientToServerAEAD = nil
		client.serverToClientAEAD = nil
		client.wssReadChan = nil
		client.wssWriteChan = nil
		client.tapReadChan = nil
		client.tapWriteChan = nil
		client.wssReadErrChan = nil
		client.wssWriteErrChan = nil
		client.tapReadErrChan = nil
		client.tapWriteErrChan = nil
		client.linkCtx = nil
		client.linkCancel = nil
	})
	return errs
}

// After Shutdown, the related object should be DROPPED, do NOT reuse it!
func (client *RoxyClient) Shutdown() error {
	client.LogToAll(shared.LogLevelInfo, "Shutdown required.")

	var errs error

	// Disconnect.
	err := client.Disconnect()
	if err != nil {
		errs = errors.Join(errs, err)
	}

	if client.logCancel != nil {
		client.logCancel()
	}

	// Close DB connection.
	if client.dbConn != nil {
		err := client.dbConn.Close()
		if err != nil {
			errs = errors.Join(errs, err)
		} else {
			client.dbConn = nil
		}
	}

	// Return joined errors.
	return errs
}
