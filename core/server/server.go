/*
 * @Author: FunctionSir
 * @License: AGPLv3
 * @Date: 2025-09-21 10:55:57
 * @LastEditTime: 2025-11-29 23:18:59
 * @LastEditors: FunctionSir
 * @Description: -
 * @FilePath: /roxytunnel/core/server/server.go
 */

package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"net/http"
	"sync"

	"github.com/FunctionSir/roxytunnel/core/shared"
	"github.com/coder/websocket"
	"github.com/flynn/noise"
	"github.com/songgao/water"
)

type LinkSession struct {
	sessionID                         string
	clientUID                         string
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
	clientToServerAntiReplayChecker   *shared.AntiReplayChecker
	serverToClientAntiReplayGenerator *shared.AntiReplayGenerator
	linkCtx                           context.Context
	linkCancel                        context.CancelFunc
	pipelineWG                        sync.WaitGroup
	disconnectOnce                    sync.Once
}

type RoxyServer struct {
	instanceDB   string
	dbConn       *sql.DB
	sessions     sync.Map
	serverCtx    context.Context
	serverCancel context.CancelFunc
	logCtx       context.Context
	logCancel    context.CancelFunc
}

// In dev...
func (server *RoxyServer) StartLinkSession(clientUID string, conn *websocket.Conn) error {
	return nil
}

func NewRoxyServer(instanceDB string) (*RoxyServer, error) {
	// Connect to instance DB.
	db, err := sql.Open("sqlite", instanceDB)
	if err != nil {
		return &RoxyServer{instanceDB: instanceDB}, err
	}

	// TODO: Add checking of DB type (should be "server").

	// Create server context for server.
	serverCtxWithCancel, serverCtxCancel := context.WithCancel(context.Background())

	// Create log context for server.
	logCtxWithCancel, logCtxCancel := context.WithCancel(context.Background())

	// Construct and return the server instance.
	return &RoxyServer{
		instanceDB:   instanceDB,
		dbConn:       db,
		serverCtx:    serverCtxWithCancel,
		serverCancel: serverCtxCancel,
		logCtx:       logCtxWithCancel,
		logCancel:    logCtxCancel,
	}, nil
}

func (server *RoxyServer) LogToScreen(level shared.LogLevel, msg string) {
	shared.LogToScreen(level, msg)
}

func (server *RoxyServer) LogToDatabase(level shared.LogLevel, msg string) {
	shared.LogToDatabase(server.logCtx, server.dbConn, level, msg)
}

func (server *RoxyServer) LogToAll(level shared.LogLevel, msg string) {
	server.LogToScreen(level, msg)
	server.LogToDatabase(level, msg)
}

// TODO: Finish VerifyClientNoisePubKey.
func (server *RoxyServer) VerifyClientNoisePubKey(pubkey []byte) (bool, error) {
	return false, nil
}

// TODO: Finish MakeAntiReplayChecker.
func (server *RoxyServer) MakeAntiReplayChecker(pubkey []byte) (*shared.AntiReplayChecker, error) {
	return nil, nil
}

// TODO: Finish it.
func (server *RoxyServer) connectRequestHandler(w http.ResponseWriter, r *http.Request) {
	// Get client noise init data.
	clientNoiseInitStr := r.Header.Get(shared.HTTPHeaderXNoiseInit)
	if len(clientNoiseInitStr) <= 0 {
		// TODO: Add on-fail actions //
		return
	}
	clientNoiseInit, err := base64.RawURLEncoding.DecodeString(clientNoiseInitStr)
	if err != nil {
		// TODO: Add on-fail actions //
		return
	}

	// Get Noise PSK.
	var noisePSKStr string
	err = shared.GetConfVal(server.serverCtx, server.dbConn, shared.ConfKeyServerNoisePSK, &noisePSKStr)
	if err != nil {
		// TODO: Add on-fail actions //
		return
	}
	noisePSK, err := base64.RawURLEncoding.DecodeString(noisePSKStr)
	if err != nil {
		// TODO: Add on-fail actions //
		return
	}

	// Get Noise server public key.
	var serverNoisePubKeyStr string
	err = shared.GetConfVal(server.serverCtx, server.dbConn, shared.ConfKeyServerNoiseServerPublicKey, &serverNoisePubKeyStr) // TODO: Finish it.
	if err != nil {
		// TODO: Add on-fail actions //
		return
	}
	serverNoisePubKey, err := base64.RawURLEncoding.DecodeString(serverNoisePubKeyStr)
	if err != nil {
		// TODO: Add on-fail actions //
		return
	}

	// Get Noise server private key.
	var serverNoisePrivKeyStr string
	err = shared.GetConfVal(server.serverCtx, server.dbConn, shared.ConfKeyServerNoiseServerPrivateKey, &serverNoisePrivKeyStr) // TODO: Finish it.
	if err != nil {
		// TODO: Add on-fail actions //
		return
	}
	serverNoisePrivKey, err := base64.RawURLEncoding.DecodeString(serverNoisePrivKeyStr)
	if err != nil {
		// TODO: Add on-fail actions //
		return
	}

	// Assemble server Noise key pair.
	serverNoiseKeyPair := noise.DHKey{
		Private: serverNoisePrivKey,
		Public:  serverNoisePubKey,
	}

	// Construct server side noise config.
	noiseConf := noise.Config{
		CipherSuite: noise.NewCipherSuite(
			noise.DH25519,
			noise.CipherChaChaPoly,
			noise.HashSHA512,
		),
		Pattern:               noise.HandshakeIK,
		Initiator:             false, // Server is not initiator.
		StaticKeypair:         serverNoiseKeyPair,
		PeerStatic:            nil, // It's IK mode.
		Random:                rand.Reader,
		PresharedKey:          noisePSK, // Currently, all clients sharing the same PSK.
		PresharedKeyPlacement: 2,        // Use PSK2 to get a better forward security performance.
	}
	noiseHandshake, err := noise.NewHandshakeState(noiseConf)
	if err != nil {
		// TODO: Add on-fail actions //
		return
	}

	clientDataWithARH, csC2S, csS2C, err := noiseHandshake.ReadMessage(nil, clientNoiseInit)
	if err != nil {
		// TODO: Add on-fail actions //
		return
	}

	arHeader, clientData, err := shared.SplitAntiReplayHeader(clientDataWithARH)
	if err != nil {
		// TODO: Add on-fail actions //
		return
	}

	// Get client Noise public key.
	clientNoisePubKey := noiseHandshake.PeerStatic()

	// Auth client.
	clientAuthOK, err := server.VerifyClientNoisePubKey(clientNoisePubKey)
	if err != nil {
		// TODO: Add on-fail actions //
		return
	}
	if !clientAuthOK {
		// TODO: Add on-fail actions //
		return
	}

	// Check is replay or not.
	antiReplayChecker, err := server.MakeAntiReplayChecker(clientNoisePubKey)
	if err != nil {
		// TODO: Add on-fail actions //
		return
	}
	notReplay, _, err := antiReplayChecker.Check(arHeader)
	if err != nil {
		// TODO: Add on-fail actions //
		return
	}
	if !notReplay {
		// TODO: Add on-fail actions //
		return
	}

	// Update anti replay status.
	// TODO: In Dev... //
}

func (server *RoxyServer) ListenAndServe() error {
	// Get Listen Address.
	var listenAddr string
	err := shared.GetConfVal(server.serverCtx, server.dbConn, shared.ConfKeyServerListen, &listenAddr)
	if err != nil {
		server.LogToAll(shared.LogLevelFatal, "Can not get listen address for HTTPS server.")
	}
	// TODO: More error log accuracy.
	// Construct TLS config.
	tlsConf := &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Start a transaction, since cert should match key.
			tx, err := server.dbConn.BeginTx(server.serverCtx, nil)
			if err != nil {
				server.LogToAll(shared.LogLevelError, "Can not start DB transaction, error: "+err.Error())
				return nil, err
			}
			defer func() { _ = tx.Rollback() }()
			var certStr, keyStr string
			err = shared.GetConfValTx(server.serverCtx, tx, shared.ConfKeyServerTLSCert, &certStr)
			if err != nil {
				server.LogToAll(shared.LogLevelError, "Can not read TLS cert, might be a malformed instance DB.")
				return nil, err
			}
			err = shared.GetConfValTx(server.serverCtx, tx, shared.ConfKeyServerTLSKey, &keyStr)
			if err != nil {
				server.LogToAll(shared.LogLevelError, "Can not read TLS key, might be a malformed instance DB.")
				return nil, err
			}
			err = tx.Commit()
			if err != nil {
				server.LogToAll(shared.LogLevelError, "Can not commit DB transaction, error: "+err.Error())
				return nil, err
			}
			cert, err := base64.RawURLEncoding.DecodeString(certStr)
			if err != nil {
				server.LogToAll(shared.LogLevelError, "Can not decode TLS cert, might be a malformed PEM cert.")
				return nil, err
			}
			key, err := base64.RawURLEncoding.DecodeString(keyStr)
			if err != nil {
				server.LogToAll(shared.LogLevelError, "Can not decode TLS key, might be a malformed PEM cert.")
				return nil, err
			}
			wholeCert, err := tls.X509KeyPair(cert, key)
			if err != nil {
				server.LogToAll(shared.LogLevelError, "Can not assemble TLS cert, error: "+err.Error()+".")
				return nil, err
			}
			// TODO: Add cert validation.
			return &wholeCert, nil
		},
	}

	// Construct ServeMux.
	// TODO: Add 404-not-found custom meek.
	mux := http.NewServeMux()
	// Get entry path.
	var entryPath string
	err = shared.GetConfVal(server.serverCtx, server.dbConn, shared.ConfKeyServerEntryPath, &entryPath)
	if err != nil {
		server.LogToAll(shared.LogLevelFatal, "Can not get entry path for HTTPS server.")
	}
	mux.HandleFunc(entryPath, server.connectRequestHandler)

	// Construct HTTPS Server
	httpsServer := &http.Server{
		Addr:      listenAddr,
		TLSConfig: tlsConf,
		Handler:   mux,
	}

	// Listen and serve
	return httpsServer.ListenAndServeTLS("", "")
}
