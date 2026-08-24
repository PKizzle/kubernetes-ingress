package handler

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/haproxytech/client-native/v6/models"
	"github.com/haproxytech/kubernetes-ingress/pkg/annotations"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy/instance"
	"github.com/haproxytech/kubernetes-ingress/pkg/service"
	"github.com/haproxytech/kubernetes-ingress/pkg/store"
)

type TCPServices struct {
	CertDir  string
	AddrIPv4 string
	AddrIPv6 string
	IPv4     bool
	IPv6     bool
}

type tcpSvcParser struct {
	service    *store.Service
	port       int64
	sslOffload bool
}

func (handler TCPServices) Update(k store.K8s, h haproxy.HAProxy, a annotations.Annotations) error {
	if k.ConfigMaps.TCPServices == nil {
		return nil
	}
	handler.clearFrontends(k, h)
	var p tcpSvcParser
	logFormat := k.ConfigMaps.TCPServices.Annotations["log-format-tcp"]

	for port, tcpSvcAnn := range k.ConfigMaps.TCPServices.Annotations {
		if port == "log-format-tcp" {
			continue
		}
		frontendName := "tcp-" + port
		var err error
		p, err = handler.parseTCPService(k, tcpSvcAnn)
		if err != nil {
			logger.Error(err)
			continue
		}
		frontend, errGet := h.FrontendGet(frontendName)
		if errGet != nil {
			frontend = models.Frontend{
				FrontendBase: models.FrontendBase{
					Name: frontendName,
					Mode: "tcp",
				},
			}
		}

		if logFormat != "" {
			frontend.LogFormat = "'" + strings.TrimSpace(logFormat) + "'"
			frontend.Tcplog = false
		} else {
			frontend.LogFormat = ""
			frontend.Tcplog = true
		}

		// Create Frontend
		if errGet != nil {
			if err := handler.createTCPFrontend(h, frontend, port, p.sslOffload); err != nil {
				logger.Error(err)
				continue
			}
		}

		// Update  Frontend
		err = handler.updateTCPFrontend(k, h, frontend, p, a)
		if err != nil {
			logger.Errorf("TCP frontend '%s': update failed: %s", frontendName, err)
		}
	}
	return nil
}

func (handler TCPServices) parseTCPService(store store.K8s, input string) (p tcpSvcParser, err error) {
	// parts[0]: Service Name
	// parts[1]: Service Port
	// parts[2]: SSL option
	parts := strings.Split(input, ":")
	if len(parts) < 2 {
		err = fmt.Errorf("incorrect format '%s', 'ServiceName:ServicePort' is required", input)
		return p, err
	}
	svcName := strings.Split(parts[0], "/")
	svcPort := parts[1]
	if len(parts) > 2 {
		if parts[2] == "ssl" {
			p.sslOffload = true
		}
	}
	if len(svcName) != 2 {
		err = fmt.Errorf("incorrect Service Name '%s'. Should be in 'ServiceNS/ServiceName' format", parts[0])
		return p, err
	}
	namespace := svcName[0]
	service := svcName[1]
	var ok bool
	if _, ok = store.Namespaces[namespace]; !ok {
		err = fmt.Errorf("tcp-services: namespace of service '%s/%s' not found", namespace, service)
		return p, err
	}
	p.service, ok = store.Namespaces[namespace].Services[service]
	if !ok {
		err = fmt.Errorf("tcp-services: service '%s/%s' not found", namespace, service)
		return p, err
	}
	if p.port, err = strconv.ParseInt(svcPort, 10, 64); err != nil {
		return p, err
	}
	return p, err
}

func (handler TCPServices) clearFrontends(k store.K8s, h haproxy.HAProxy) {
	frontends, err := h.FrontendsGet()
	if err != nil {
		logger.Error(err)
		return
	}
	for _, ft := range frontends {
		_, isRequired := k.ConfigMaps.TCPServices.Annotations[strings.TrimPrefix(ft.Name, "tcp-")]
		isTCPSvc := strings.HasPrefix(ft.Name, "tcp-")
		if isTCPSvc && !isRequired {
			err := h.FrontendDelete(ft.Name)
			if err != nil {
				logger.Errorf("error deleting tcp frontend '%s': %s", ft.Name, err)
			}
			instance.ReloadIf(err == nil, "TCP frontend '%s' deleted", ft.Name)
		}
	}
}

func (handler TCPServices) createTCPFrontend(h haproxy.HAProxy, frontend models.Frontend, bindPort string, sslOffload bool) error {
	var errs []error
	errs = append(errs, h.FrontendCreate(frontend.FrontendBase))
	if handler.IPv4 {
		errs = append(errs, h.FrontendBindCreate(frontend.Name, models.Bind{
			Name:       "v4",
			Address:    handler.AddrIPv4 + ":" + bindPort,
			BindParams: models.BindParams{},
		}))
	}
	if handler.IPv6 {
		errs = append(errs, h.FrontendBindCreate(frontend.Name, models.Bind{
			Name:    "v6",
			Address: handler.AddrIPv6 + ":" + bindPort,
			BindParams: models.BindParams{
				V4v6: true,
			},
		}))
	}
	if sslOffload {
		errs = append(errs, h.FrontendEnableSSLOffload(frontend.Name, handler.CertDir, "", false, ""))
	}
	if joinedErr := errors.Join(errs...); joinedErr != nil {
		return fmt.Errorf("error configuring tcp frontend: %w", joinedErr)
	}
	instance.Reload("TCP frontend '%s' created", frontend.Name)
	return nil
}

func (handler TCPServices) updateTCPFrontend(k store.K8s, h haproxy.HAProxy, frontend models.Frontend, p tcpSvcParser, a annotations.Annotations) error {
	prevFrontend, err := h.FrontendGet(frontend.Name)
	if err != nil {
		return fmt.Errorf("failed to get frontend '%s' : %w", frontend.Name, err)
	}

	if prevFrontend.LogFormat != frontend.LogFormat {
		if err := h.FrontendEdit(frontend.FrontendBase); err != nil {
			return err
		}

		instance.Reload("log format TCP changed from configmap '%s/%s'", k.ConfigMaps.TCPServices.Namespace, k.ConfigMaps.TCPServices.Name)
	}
	binds, err := h.FrontendBindsGet(frontend.Name)
	if err != nil {
		return fmt.Errorf("failed to get bind lines: %w", err)
	}
	if !binds[0].Ssl && p.sslOffload {
		if err := h.FrontendEnableSSLOffload(frontend.Name, handler.CertDir, "", false, ""); err != nil {
			return fmt.Errorf("failed to enable SSL offload: %w", err)
		}
		instance.Reload("TCP frontend '%s': ssl offload enabled", frontend.Name)
	}
	if binds[0].Ssl && !p.sslOffload {
		if err := h.FrontendDisableSSLOffload(frontend.Name); err != nil {
			return fmt.Errorf("failed to disable SSL offload: %w", err)
		}
		instance.Reload("TCP frontend '%s': ssl offload disabled", frontend.Name)
	}
	if p.service.Status == store.DELETED {
		frontend.DefaultBackend = ""
		if err := h.FrontendEdit(frontend.FrontendBase); err != nil {
			return err
		}
		instance.Reload("TCP frontend '%s': service '%s/%s' deleted", frontend.Name, p.service.Namespace, p.service.Name)
		return nil
	}

	path := &store.IngressPath{
		SvcNamespace:     p.service.Namespace,
		SvcName:          p.service.Name,
		SvcPortInt:       p.port,
		IsDefaultBackend: true,
	}
	var svc *service.Service
	svc, err = service.New(k, path, nil, true, nil, k.ConfigMaps.Main.Annotations)
	if err == nil {
		return svc.SetDefaultBackend(k, h, []string{frontend.Name}, a)
	}
	return err
}
