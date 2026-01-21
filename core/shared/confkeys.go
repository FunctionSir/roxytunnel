/*
 * @Author: FunctionSir
 * @License: AGPLv3
 * @Date: 2025-09-21 16:41:19
 * @LastEditTime: 2025-11-27 21:48:04
 * @LastEditors: FunctionSir
 * @Description: -
 * @FilePath: /roxytunnel/core/shared/confkeys.go
 */

package shared

// Official config keys for Roxy Tunnel

// Client side config keys
const (
	ConfKeyClientServer                        string = "client.server"                           // Example: "wss://example.org:8443"
	ConfKeyClientHeadersLengthRandomPaddingMin string = "client.header_length_random_padding.min" // Example: "32"
	ConfKeyClientHeadersLengthRandomPaddingMax string = "client.header_length_random_padding.max" // Example: "128"
	ConfKeyClientAuthMethod                    string = "client.auth.method"                      // Example: "bearer"
	ConfKeyClientAuthPayload                   string = "client.auth.payload"                     // Value is auth payload
	ConfKeyClientTLSVerifyMode                 string = "client.tls.verify.mode"                  // Example: "strict"
	ConfKeyClientTLSServerName                 string = "client.tls.server_name"                  // Example: "example.org"
	ConfKeyClientTLSMeek                       string = "client.tls.meek"                         // Example: "chrome"
	ConfKeyClientTLSCertPinning                string = "client.tls.cert_pinning"                 // Example: "pubkey"
	ConfKeyClientTLSCertPinned                 string = "client.tls.cert_pinned"                  // Value is the hash of whole cert or public key
	ConfKeyClientNoiseServerPublicKey          string = "client.noise.server.public_key"          // Value is Base64 encoded Noise public key of server
	ConfKeyClientNoiseClientPublicKey          string = "client.noise.client.public_key"          // Value is Base64 encoded Noise public key of client
	ConfKeyClientNoiseClientPrivateKey         string = "client.noise.client.private_key"         // Value is Base64 encoded Noise private key of client
	ConfKeyClientNoisePSK                      string = "client.noise.psk"                        // Value is Base64 encoded Noise PSK for post-quantum security
	ConfKeyClientInboundProcessorPath          string = "client.processor.inbound.path"           // Example: "/opt/demoprocessor"
	ConfKeyClientInboundProcessorArgs          string = "client.processor.inbound.args"           // Example: "-in"
	ConfKeyClientOutboundProcessorPath         string = "client.processor.outbound.path"          // Example: "/opt/demoprocessor"
	ConfKeyClientOutboundProcessorArgs         string = "client.processor.outbound.args"          // Example: "-out"
)

// Server side config keys
const (
	ConfKeyServerListen                string = "server.listen"                   // Example: "127.0.0.1:8443"
	ConfKeyServerTransport             string = "server.transport"                // Currently, value should be "wss" only
	ConfKeyServerTLSCert               string = "server.tls.cert"                 // Value is Base64 encoded cert data (PEM format)
	ConfKeyServerTLSKey                string = "server.tls.key"                  // Value is Base64 encoded cert key data (PEM format)
	ConfKeyServerAuthType              string = "server.auth.type"                // Example: "bearer"
	ConfKeyServerEntryPath             string = "server.entry_path"               // Example: "/a702a023-d435-481f-83ab-7563c978e5ac"
	ConfKeyServerAuthOnFailAction      string = "server.auth.on_fail.action"      // Example: "meek"
	ConfKeyServerAuthOnFailArgs        string = "server.auth.on_fail.args"        // Example: "nginx.403"
	ConfKeyServerNoisePSK              string = "server.noise.psk"                // Value is Base64 encoded Noise PSK for post-quantum security
	ConfKeyServerNoiseServerPublicKey  string = "server.noise.server.public_key"  // Value is Base64 encoded Noise public key of server
	ConfKeyServerNoiseServerPrivateKey string = "server.noise.server.private_key" // Value is Base64 encoded Noise private key of server
	ConfKeyServerInboundProcessorPath  string = "server.processor.inbound.path"   // Example: "/opt/demoprocessor"
	ConfKeyServerInboundProcessorArgs  string = "server.processor.inbound.args"   // Example: "-in"
	ConfKeyServerOutboundProcessorPath string = "server.processor.outbound.path"  // Example: "/opt/demoprocessor"
	ConfKeyServerOutboundProcessorArgs string = "server.processor.outbound.args"  // Example: "-out"
)

// Nuke related config keys
const (
	ConfKeyNukeOverwritePasses  string = "nuke.overwrite.passes"  // Example: "3"
	ConfKeyNukeOverwritePattern string = "nuke.overwrite.pattern" // Example: "01R"
	ConfKeyNukePostNuke         string = "nuke.post_nuke"         // Example: "reboot_to_memtest86+.sh"
)
