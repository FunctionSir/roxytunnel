/*
 * @Author: FunctionSir
 * @License: AGPLv3
 * @Date: 2025-09-21 10:55:57
 * @LastEditTime: 2025-11-25 20:07:17
 * @LastEditors: FunctionSir
 * @Description: -
 * @FilePath: /roxytunnel/core/server/server.go
 */

package server

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"

	"github.com/FunctionSir/roxytunnel/core/shared"
	"github.com/coder/websocket"
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
	serverToClientAntiReplayChecker   *shared.AntiReplayChecker
	clientToServerAntiReplayGenerator *shared.AntiReplayGenerator
	linkCtx                           context.Context
	linkCancel                        context.CancelFunc
	pipelineWG                        sync.WaitGroup
	disconnectOnce                    sync.Once
}

type RoxyServer struct {
	instanceDB   string
	dbConn       *sql.DB
	authMethod   shared.RoxyAuthMethod
	sessions     sync.Map
	serverCtx    context.Context
	serverCancel context.CancelFunc
	logCtx       context.Context
	logCancel    context.CancelFunc
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

// TODO: Finish it.
func connectRequestHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get(shared.HTTPHeaderAuthorization)
	splited := strings.Split(authHeader, " ")
	if len(splited) != 2 { // Invalid format of auth header.
		// TODO: Replace it with on Fail func.
		return
	}
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
	mux.HandleFunc(entryPath, func(w http.ResponseWriter, r *http.Request) {
		// TODO: Finsish it.
	})

	// Construct HTTPS Server
	httpsServer := &http.Server{
		Addr:      listenAddr,
		TLSConfig: tlsConf,
		Handler:   mux,
	}

	// Listen and serve
	return httpsServer.ListenAndServeTLS("", "")
}
