package api

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/haproxytech/client-native/v6/models"

	"github.com/haproxytech/kubernetes-ingress/pkg/controller/constants"
)

var (
	ErrRuntimeDynamicNotAvailable = errors.New("runtime dynamic backend management is not available")
	ErrRuntimeBackendNotEligible  = errors.New("backend is not eligible for runtime dynamic backend management")
	ErrRuntimeServerNotEligible   = errors.New("server is not eligible for runtime dynamic backend management")

	haproxyVersionRE = regexp.MustCompile(`\b([0-9]+)\.([0-9]+)(?:[.-][^\s]*)?`)
)

type RuntimeCapabilities struct {
	HAProxyVersion                   string
	HAProxyVersionMajor              int
	HAProxyVersionMinor              int
	DynamicBackendManagement         bool
	DynamicServers                   bool
	DynamicBackendManagementDisabled bool
}

func (c *clientNative) RuntimeCapabilities() RuntimeCapabilities {
	if c.runtimeCapabilitiesChecked {
		return c.runtimeCapabilities
	}

	c.runtimeCapabilities = RuntimeCapabilities{
		DynamicBackendManagementDisabled: c.dynamicBackendManagementDisabled,
	}
	if c.dynamicBackendManagementDisabled {
		c.runtimeCapabilitiesChecked = true
		return c.runtimeCapabilities
	}

	version, err := c.ExecuteRaw("show version")
	if err != nil {
		logger.Debugf("[RUNTIME] [CAPABILITY] unable to query HAProxy runtime version: %s", err)
		return c.runtimeCapabilities
	}
	major, minor, ok := parseHAProxyRuntimeVersion(version)
	c.runtimeCapabilities.HAProxyVersion = strings.TrimSpace(version)
	c.runtimeCapabilities.HAProxyVersionMajor = major
	c.runtimeCapabilities.HAProxyVersionMinor = minor
	c.runtimeCapabilitiesChecked = true
	if !ok {
		logger.Debugf("[RUNTIME] [CAPABILITY] unable to parse HAProxy runtime version from %q", strings.TrimSpace(version))
		return c.runtimeCapabilities
	}

	if major > 3 || (major == 3 && minor >= 4) {
		c.runtimeCapabilities.DynamicBackendManagement = true
		c.runtimeCapabilities.DynamicServers = true
	}
	return c.runtimeCapabilities
}

func parseHAProxyRuntimeVersion(version string) (major, minor int, ok bool) {
	match := haproxyVersionRE.FindStringSubmatch(version)
	if len(match) != 3 {
		return 0, 0, false
	}
	major, errMajor := strconv.Atoi(match[1])
	minor, errMinor := strconv.Atoi(match[2])
	return major, minor, errMajor == nil && errMinor == nil
}

func (c *clientNative) RuntimeBackendCreate(backendName string) error {
	capabilities := c.RuntimeCapabilities()
	if !capabilities.DynamicBackendManagement {
		return ErrRuntimeDynamicNotAvailable
	}
	backend, ok := c.backends[backendName]
	if !ok {
		return fmt.Errorf("backend %s: %w", backendName, ErrNotFound)
	}
	if err := backendRuntimeEligible(backend); err != nil {
		return err
	}

	from := backend.From
	if from == "" {
		from = constants.DefaultsSectionName
	}
	cmd := "experimental-mode on;add backend " + runtimeSafeToken(backendName) + " from " + runtimeSafeToken(from)
	if backend.Mode != "" {
		cmd += " mode " + runtimeSafeToken(backend.Mode)
	}
	if backend.GUID != "" {
		cmd += " guid " + runtimeSafeToken(backend.GUID)
	}
	cmd += ";publish backend " + runtimeSafeToken(backendName)

	if _, err := c.ExecuteRaw(cmd); err != nil {
		return fmt.Errorf("runtime create backend %s: %w", backendName, err)
	}
	c.runtimeCreatedBackends[backendName] = struct{}{}
	logger.Infof("[RUNTIME] [BACKEND] dynamically created and published backend '%s'", backendName)
	return nil
}

func (c *clientNative) RuntimeBackendPublish(backendName string) error {
	if !c.RuntimeCapabilities().DynamicBackendManagement {
		return ErrRuntimeDynamicNotAvailable
	}
	_, err := c.ExecuteRaw("publish backend " + runtimeSafeToken(backendName))
	return err
}

func (c *clientNative) RuntimeBackendUnpublish(backendName string) error {
	if !c.RuntimeCapabilities().DynamicBackendManagement {
		return ErrRuntimeDynamicNotAvailable
	}
	_, err := c.ExecuteRaw("unpublish backend " + runtimeSafeToken(backendName))
	return err
}

func (c *clientNative) RuntimeBackendDelete(backendName string) error {
	if !c.RuntimeCapabilities().DynamicBackendManagement {
		return ErrRuntimeDynamicNotAvailable
	}
	cmd := "experimental-mode on;unpublish backend " + runtimeSafeToken(backendName) + ";wait be-removable " + runtimeSafeToken(backendName) + ";del backend " + runtimeSafeToken(backendName)
	_, err := c.ExecuteRaw(cmd)
	return err
}

func (c *clientNative) RuntimeServerAdd(backendName string, server models.Server, defaultServer *models.DefaultServer) error {
	if !c.RuntimeCapabilities().DynamicServers {
		return ErrRuntimeDynamicNotAvailable
	}
	if backendName == "" || server.Name == "" {
		return fmt.Errorf("backend %q server %q: %w", backendName, server.Name, ErrRuntimeServerNotEligible)
	}
	attributes, err := runtimeServerAttributes(server, defaultServer)
	if err != nil {
		return err
	}
	runtime, err := c.nativeAPI.Runtime()
	if err != nil {
		return err
	}
	if err = runtime.AddServer(runtimeSafeToken(backendName), runtimeSafeToken(server.Name), attributes); err != nil {
		return fmt.Errorf("runtime add server %s/%s: %w", backendName, server.Name, err)
	}
	// "add server" instantiates the server in maintenance. Unless it is meant to stay
	// disabled it has to be enabled explicitly, otherwise the backend keeps answering
	// 503 with no server available.
	if effectiveServerParams(server.ServerParams, defaultServer).Maintenance != "enabled" {
		if err = runtime.EnableServer(runtimeSafeToken(backendName), runtimeSafeToken(server.Name)); err != nil {
			return fmt.Errorf("runtime enable server %s/%s: %w", backendName, server.Name, err)
		}
	}
	// Only record the server once it is actually serving: the caller relies on this to
	// decide whether the reload that would apply the configuration file can be skipped.
	c.recordRuntimeCreatedServer(backendName, server.Name)
	logger.Infof("[RUNTIME] [BACKEND] [SERVER] dynamically added server '%s/%s'", backendName, server.Name)
	return nil
}

func (c *clientNative) RuntimeServerDrainAndDelete(backendName, serverName string) error {
	if !c.RuntimeCapabilities().DynamicServers {
		return ErrRuntimeDynamicNotAvailable
	}
	backend := runtimeSafeToken(backendName)
	server := runtimeSafeToken(serverName)
	serverRef := backend + "/" + server
	cmd := "disable server " + serverRef + ";shutdown sessions server " + serverRef + ";wait srv-removable " + serverRef + ";del server " + serverRef
	if _, err := c.ExecuteRaw(cmd); err != nil {
		// The leading "disable server" of the sequence has already been applied, so put the
		// server back in rotation rather than leaving it stranded in maintenance.
		runtimeClient, errRuntime := c.nativeAPI.Runtime()
		if errRuntime == nil {
			errRuntime = runtimeClient.EnableServer(backend, server)
		}
		if errRuntime != nil {
			logger.Errorf("[RUNTIME] [BACKEND] [SERVER] unable to restore server '%s' after a failed drain: %s", serverRef, errRuntime)
		}
		return err
	}
	if servers, ok := c.runtimeCreatedServers[backendName]; ok {
		delete(servers, serverName)
	}
	logger.Infof("[RUNTIME] [BACKEND] [SERVER] dynamically deleted server '%s/%s'", backendName, serverName)
	return nil
}

func backendRuntimeEligible(backend Backend) error {
	if len(backend.ConfigSnippets) > 0 ||
		len(backend.ACLList) > 0 ||
		len(backend.HTTPRequestRuleList) > 0 ||
		len(backend.HTTPResponseRuleList) > 0 ||
		len(backend.HTTPAfterResponseRuleList) > 0 ||
		len(backend.ServerSwitchingRuleList) > 0 ||
		len(backend.StickRuleList) > 0 ||
		len(backend.TCPRequestRuleList) > 0 ||
		len(backend.TCPResponseRuleList) > 0 ||
		len(backend.FilterList) > 0 ||
		len(backend.HTTPCheckList) > 0 ||
		len(backend.LogTargetList) > 0 ||
		len(backend.HTTPErrorRuleList) > 0 ||
		len(backend.TCPCheckRuleList) > 0 {
		return ErrRuntimeBackendNotEligible
	}

	base := backend.BackendBase
	base.Name = ""
	base.Mode = ""
	base.From = ""
	base.GUID = ""
	base.DefaultServer = nil
	if base.Balance != nil {
		if !runtimeDefaultBalance(base.Balance) {
			return fmt.Errorf("backend %s has non-default balance settings: %w", backend.Name, ErrRuntimeBackendNotEligible)
		}
		base.Balance = nil
	}
	if !reflect.ValueOf(base).IsZero() {
		return fmt.Errorf("backend %s has backend options that cannot be applied at runtime: %w", backend.Name, ErrRuntimeBackendNotEligible)
	}
	return nil
}

func runtimeDefaultBalance(balance *models.Balance) bool {
	if balance == nil || balance.Algorithm == nil {
		return true
	}
	copyBalance := *balance
	algorithm := *copyBalance.Algorithm
	copyBalance.Algorithm = nil
	return algorithm == "roundrobin" && reflect.ValueOf(copyBalance).IsZero()
}

func runtimeServerAttributes(server models.Server, defaultServer *models.DefaultServer) (string, error) {
	if server.Address == "" {
		return "", fmt.Errorf("server %s has no address: %w", server.Name, ErrRuntimeServerNotEligible)
	}
	params := effectiveServerParams(server.ServerParams, defaultServer)
	if err := unsupportedRuntimeServerParams(params); err != nil {
		return "", err
	}

	attributes := []string{formatRuntimeServerAddress(server.Address, server.Port)}
	addEnabledKeyword := func(keyword, value string) {
		if value == "enabled" {
			attributes = append(attributes, keyword)
		}
	}
	addKeywordValue := func(keyword, value string) error {
		if value == "" {
			return nil
		}
		if strings.ContainsAny(value, " \t\n\r;") {
			return fmt.Errorf("server %s has unsupported whitespace in %s: %w", server.Name, keyword, ErrRuntimeServerNotEligible)
		}
		attributes = append(attributes, keyword, value)
		return nil
	}
	addKeywordInt := func(keyword string, value *int64) {
		if value != nil {
			attributes = append(attributes, keyword, strconv.FormatInt(*value, 10))
		}
	}

	if params.Maintenance == "enabled" {
		attributes = append(attributes, "disabled")
	}
	addEnabledKeyword("check", params.Check)
	addEnabledKeyword("agent-check", params.AgentCheck)
	addEnabledKeyword("backup", params.Backup)
	addEnabledKeyword("check-send-proxy", params.CheckSendProxy)
	addEnabledKeyword("check-ssl", params.CheckSsl)
	addEnabledKeyword("send-proxy", params.SendProxy)
	addEnabledKeyword("send-proxy-v2", params.SendProxyV2)
	addEnabledKeyword("send-proxy-v2-ssl", params.SendProxyV2Ssl)
	addEnabledKeyword("send-proxy-v2-ssl-cn", params.SendProxyV2SslCn)
	addEnabledKeyword("ssl", params.Ssl)
	addEnabledKeyword("tfo", params.Tfo)

	for _, value := range []struct{ keyword, text string }{
		{"agent-addr", params.AgentAddr},
		{"agent-send", params.AgentSend},
		{"alpn", params.Alpn},
		{"check-alpn", params.CheckAlpn},
		{"check-proto", params.CheckProto},
		{"check-sni", params.CheckSni},
		{"cookie", params.Cookie},
		{"init-addr", stringPtrValue(params.InitAddr)},
		{"init-state", params.InitState},
		{"proto", params.Proto},
		{"resolve-net", params.ResolveNet},
		{"resolve-opts", params.ResolveOpts},
		{"resolve-prefer", params.ResolvePrefer},
		{"resolvers", params.Resolvers},
		{"sni", params.Sni},
		{"ssl-cafile", params.SslCafile},
		{"ssl-certificate", params.SslCertificate},
		{"ssl-max-ver", params.SslMaxVer},
		{"ssl-min-ver", params.SslMinVer},
		{"verify", params.Verify},
		{"verifyhost", params.Verifyhost},
		{"ws", params.Ws},
	} {
		if err := addKeywordValue(value.keyword, value.text); err != nil {
			return "", err
		}
	}

	addKeywordInt("agent-inter", params.AgentInter)
	addKeywordInt("agent-port", params.AgentPort)
	addKeywordInt("downinter", params.Downinter)
	addKeywordInt("fall", params.Fall)
	addKeywordInt("fastinter", params.Fastinter)
	addKeywordInt("inter", params.Inter)
	addKeywordInt("maxconn", params.Maxconn)
	addKeywordInt("maxqueue", params.Maxqueue)
	addKeywordInt("minconn", params.Minconn)
	addKeywordInt("rise", params.Rise)
	addKeywordInt("slowstart", params.Slowstart)
	addKeywordInt("weight", params.Weight)
	if params.HealthCheckAddress != "" {
		if err := addKeywordValue("check-addr", params.HealthCheckAddress); err != nil {
			return "", err
		}
	}
	if params.HealthCheckPort != nil {
		attributes = append(attributes, "check", "port", strconv.FormatInt(*params.HealthCheckPort, 10))
	}

	return strings.Join(attributes, " "), nil
}

func effectiveServerParams(serverParams models.ServerParams, defaultServer *models.DefaultServer) models.ServerParams {
	if defaultServer == nil {
		return serverParams
	}
	params := defaultServer.ServerParams
	overlayServerParams(&params, serverParams)
	return params
}

func overlayServerParams(target *models.ServerParams, overlay models.ServerParams) {
	targetValue := reflect.ValueOf(target).Elem()
	overlayValue := reflect.ValueOf(overlay)
	for i := 0; i < overlayValue.NumField(); i++ {
		field := overlayValue.Field(i)
		if !field.IsZero() {
			targetValue.Field(i).Set(field)
		}
	}
}

func unsupportedRuntimeServerParams(params models.ServerParams) error {
	allowed := map[string]struct{}{
		"AgentAddr": {}, "AgentCheck": {}, "AgentInter": {}, "AgentPort": {}, "AgentSend": {},
		"Alpn": {}, "Backup": {}, "Check": {}, "CheckAlpn": {}, "CheckProto": {}, "CheckSendProxy": {}, "CheckSni": {}, "CheckSsl": {},
		"Cookie": {}, "Downinter": {}, "Fall": {}, "Fastinter": {}, "HealthCheckAddress": {}, "HealthCheckPort": {},
		"InitAddr": {}, "InitState": {}, "Inter": {}, "Maintenance": {}, "Maxconn": {}, "Maxqueue": {}, "Minconn": {},
		"Proto": {}, "ResolveNet": {}, "ResolveOpts": {}, "ResolvePrefer": {}, "Resolvers": {}, "Rise": {},
		"SendProxy": {}, "SendProxyV2": {}, "SendProxyV2Ssl": {}, "SendProxyV2SslCn": {}, "Slowstart": {}, "Sni": {},
		"Ssl": {}, "SslCafile": {}, "SslCertificate": {}, "SslMaxVer": {}, "SslMinVer": {}, "Tfo": {}, "Verify": {}, "Verifyhost": {}, "Weight": {}, "Ws": {},
	}
	value := reflect.ValueOf(params)
	typeValue := value.Type()
	for i := 0; i < value.NumField(); i++ {
		if value.Field(i).IsZero() {
			continue
		}
		fieldName := typeValue.Field(i).Name
		if _, ok := allowed[fieldName]; !ok {
			return fmt.Errorf("server parameter %s cannot be rendered for runtime add server: %w", fieldName, ErrRuntimeServerNotEligible)
		}
	}
	return nil
}

func formatRuntimeServerAddress(address string, port *int64) string {
	if port == nil {
		return runtimeSafeToken(address)
	}
	return net.JoinHostPort(address, strconv.FormatInt(*port, 10))
}

func runtimeSafeToken(value string) string {
	return strings.NewReplacer(" ", "_", "\t", "_", "\n", "_", "\r", "_", ";", "_").Replace(value)
}

func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (c *clientNative) recordRuntimeCreatedServer(backendName, serverName string) {
	servers := c.runtimeCreatedServers[backendName]
	if servers == nil {
		servers = make(map[string]struct{})
		c.runtimeCreatedServers[backendName] = servers
	}
	servers[serverName] = struct{}{}
}

func (c *clientNative) runtimeServerCreated(backendName, serverName string) bool {
	servers := c.runtimeCreatedServers[backendName]
	if servers == nil {
		return false
	}
	_, ok := servers[serverName]
	return ok
}

func (c *clientNative) resetRuntimeCreatedObjects() {
	clear(c.runtimeCreatedBackends)
	clear(c.runtimeCreatedServers)
}
