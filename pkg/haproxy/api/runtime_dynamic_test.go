package api

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	clientnative "github.com/haproxytech/client-native/v6"
	"github.com/haproxytech/client-native/v6/models"
	"github.com/haproxytech/client-native/v6/options"
	"github.com/haproxytech/client-native/v6/runtime"
	runtimeoptions "github.com/haproxytech/client-native/v6/runtime/options"
)

func TestParseHAProxyRuntimeVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantMajor   int
		wantMinor   int
		wantSuccess bool
	}{
		{name: "dev version", input: "3.4-dev13-21 2026/05/20", wantMajor: 3, wantMinor: 4, wantSuccess: true},
		{name: "release banner", input: "HAProxy version 3.4.1-a1b2c3 2026/06/01", wantMajor: 3, wantMinor: 4, wantSuccess: true},
		{name: "old version", input: "HAProxy version 3.3.10", wantMajor: 3, wantMinor: 3, wantSuccess: true},
		{name: "not a version", input: "unknown", wantSuccess: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			major, minor, ok := parseHAProxyRuntimeVersion(tt.input)
			if ok != tt.wantSuccess {
				t.Fatalf("parseHAProxyRuntimeVersion() success = %t, want %t", ok, tt.wantSuccess)
			}
			if major != tt.wantMajor || minor != tt.wantMinor {
				t.Fatalf("parseHAProxyRuntimeVersion() = %d.%d, want %d.%d", major, minor, tt.wantMajor, tt.wantMinor)
			}
		})
	}
}

func TestBackendRuntimeEligible(t *testing.T) {
	t.Parallel()

	algorithm := "roundrobin"
	backend := Backend{Backend: models.Backend{BackendBase: models.BackendBase{
		Name: "default_app_80",
		Mode: "http",
		From: "haproxytech",
		Balance: &models.Balance{
			Algorithm: &algorithm,
		},
		DefaultServer: &models.DefaultServer{ServerParams: models.ServerParams{Check: "enabled"}},
	}}}
	if err := backendRuntimeEligible(backend); err != nil {
		t.Fatalf("backendRuntimeEligible() unexpected error: %v", err)
	}

	cookieName := "SRV"
	backend.Cookie = &models.Cookie{Name: &cookieName}
	if err := backendRuntimeEligible(backend); !errors.Is(err, ErrRuntimeBackendNotEligible) {
		t.Fatalf("backendRuntimeEligible() error = %v, want ErrRuntimeBackendNotEligible", err)
	}
}

func TestRuntimeServerAttributes(t *testing.T) {
	t.Parallel()

	port := int64(8080)
	server := models.Server{
		Address: "10.0.0.1",
		Name:    "SRV_1",
		Port:    &port,
		ServerParams: models.ServerParams{
			Cookie:      "SRV_1",
			Maintenance: "disabled",
		},
	}
	defaultServer := &models.DefaultServer{ServerParams: models.ServerParams{
		Alpn:   "h2,http/1.1",
		Check:  "enabled",
		Ssl:    "enabled",
		Verify: "none",
	}}

	attributes, err := runtimeServerAttributes(server, defaultServer)
	if err != nil {
		t.Fatalf("runtimeServerAttributes() unexpected error: %v", err)
	}
	for _, want := range []string{"10.0.0.1:8080", "check", "ssl", "alpn h2,http/1.1", "cookie SRV_1", "verify none"} {
		if !strings.Contains(attributes, want) {
			t.Fatalf("runtimeServerAttributes() = %q, want substring %q", attributes, want)
		}
	}

	server.AgentSend = "contains whitespace"
	if _, err = runtimeServerAttributes(server, defaultServer); !errors.Is(err, ErrRuntimeServerNotEligible) {
		t.Fatalf("runtimeServerAttributes() error = %v, want ErrRuntimeServerNotEligible", err)
	}
}

const fakeHAProxyVersion = "3.5.0"

// Commands client-native issues while initialising the runtime client. They are answered
// but kept out of the recorded command list so assertions only see the calls under test.
var runtimeProbeReplies = map[string]string{
	"show info": "Version: " + fakeHAProxyVersion,
	"help":      "",
}

// fakeRuntimeSocket is a minimal stand-in for the HAProxy runtime API: it records the
// commands it receives and answers them from a prefix-keyed reply table.
type fakeRuntimeSocket struct {
	replies  map[string]string
	mu       sync.Mutex
	commands []string
}

func newFakeRuntimeSocket(t *testing.T, replies map[string]string) (*fakeRuntimeSocket, string) {
	t.Helper()

	// Keep the directory name short: a unix socket path is limited to ~104 bytes and
	// t.TempDir() derives its name from the (long) subtest name.
	dir, err := os.MkdirTemp("", "hapi")
	if err != nil {
		t.Fatalf("unable to create temporary directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socketPath := filepath.Join(dir, "runtime.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("unable to listen on %s: %v", socketPath, err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	socket := &fakeRuntimeSocket{replies: replies}
	go func() {
		for {
			conn, errAccept := listener.Accept()
			if errAccept != nil {
				return
			}
			go socket.serve(conn)
		}
	}()
	return socket, socketPath
}

func (f *fakeRuntimeSocket) serve(conn net.Conn) {
	defer conn.Close()

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}
	command := strings.TrimPrefix(strings.TrimSpace(line), "set severity-output number;")
	if reply, isProbe := runtimeProbeReplies[command]; isProbe {
		_, _ = conn.Write([]byte(reply + "\n"))
		return
	}

	f.mu.Lock()
	f.commands = append(f.commands, command)
	reply := ""
	for prefix, candidate := range f.replies {
		if strings.HasPrefix(command, prefix) {
			reply = candidate
			break
		}
	}
	f.mu.Unlock()

	_, _ = conn.Write([]byte(reply + "\n"))
}

func (f *fakeRuntimeSocket) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

func newTestRuntimeClient(t *testing.T, socketPath string) *clientNative {
	t.Helper()

	ctx := context.Background()
	// No DoNotCheckRuntimeOnInit here: client-native has to probe the version, because it
	// refuses "add server" on anything older than HAProxy 2.6.
	runtimeClient, err := runtime.New(ctx, runtimeoptions.Socket(socketPath))
	if err != nil {
		t.Fatalf("unable to create runtime client: %v", err)
	}
	nativeAPI, err := clientnative.New(ctx, options.Runtime(runtimeClient))
	if err != nil {
		t.Fatalf("unable to create client-native client: %v", err)
	}
	return &clientNative{
		nativeAPI:                  nativeAPI,
		backends:                   make(map[string]Backend),
		frontends:                  make(map[string]*Frontend),
		runtimeCreatedBackends:     make(map[string]struct{}),
		runtimeCreatedServers:      make(map[string]map[string]struct{}),
		runtimeCapabilitiesChecked: true,
		runtimeCapabilities: RuntimeCapabilities{
			DynamicBackendManagement: true,
			DynamicServers:           true,
		},
	}
}

func testServerModel(maintenance string) models.Server {
	port := int64(8080)
	return models.Server{
		Name:         "SRV_1",
		Address:      "10.0.0.1",
		Port:         &port,
		ServerParams: models.ServerParams{Maintenance: maintenance},
	}
}

func TestRuntimeServerAdd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		replies      map[string]string
		name         string
		maintenance  string
		wantCommands []string
		wantErr      bool
		wantRecorded bool
	}{
		{
			// A server added through "add server" stays in maintenance until it is
			// explicitly enabled, otherwise the backend answers 503 with no server.
			name:         "active server is enabled after being added",
			maintenance:  "disabled",
			wantCommands: []string{"add server be/SRV_1 10.0.0.1:8080", "enable server be/SRV_1"},
			wantRecorded: true,
		},
		{
			name:         "server meant to stay in maintenance is not enabled",
			maintenance:  "enabled",
			wantCommands: []string{"add server be/SRV_1 10.0.0.1:8080 disabled"},
			wantRecorded: true,
		},
		{
			// A server that could not be enabled is not serving, so it must not be
			// recorded as created: the caller has to fall back to a reload.
			name:         "failure to enable is reported and not recorded",
			maintenance:  "disabled",
			replies:      map[string]string{"enable server": "[3]: No such server."},
			wantCommands: []string{"add server be/SRV_1 10.0.0.1:8080", "enable server be/SRV_1"},
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			socket, socketPath := newFakeRuntimeSocket(t, tt.replies)
			client := newTestRuntimeClient(t, socketPath)

			err := client.RuntimeServerAdd("be", testServerModel(tt.maintenance), nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RuntimeServerAdd() error = %v, wantErr %t", err, tt.wantErr)
			}

			commands := socket.recorded()
			if len(commands) != len(tt.wantCommands) {
				t.Fatalf("RuntimeServerAdd() commands = %v, want %v", commands, tt.wantCommands)
			}
			for i, want := range tt.wantCommands {
				if commands[i] != want {
					t.Fatalf("RuntimeServerAdd() command %d = %q, want %q", i, commands[i], want)
				}
			}
			if got := client.runtimeServerCreated("be", "SRV_1"); got != tt.wantRecorded {
				t.Fatalf("runtimeServerCreated() = %t, want %t", got, tt.wantRecorded)
			}
		})
	}
}
