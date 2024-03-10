package handler

import (
	"fmt"

	"github.com/haproxytech/client-native/v5/models"
	"github.com/haproxytech/kubernetes-ingress/pkg/annotations"
	"github.com/haproxytech/kubernetes-ingress/pkg/annotations/common"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy/instance"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy/rules"
	"github.com/haproxytech/kubernetes-ingress/pkg/store"
	"github.com/haproxytech/kubernetes-ingress/pkg/utils"
)

const (
	QUIC4BIND = "quicv4"
	QUIC6BIND = "quicv6"
)

type Quic struct {
	AddrIPv4         string
	AddrIPv6         string
	IPv4             bool
	IPv6             bool
	Enabled		     bool
	CertDir          string
	QuicAnnouncePort int64
	MaxAge           string
	QuicBindPort     int64
}

func (q *Quic) enableQUIC(h haproxy.HAProxy) (err error) {
	var binds []models.Bind
	var bindIPv4Exists, bindIPv6Exists bool

	err = q.altSvcRule(h)
	if err != nil {
		return
	}

	existingBinds, err := h.FrontendBindsGet(h.FrontHTTPS)

	if err != nil {
		return
	}

	if q.IPv4 || q.IPv6 {
		for _, existingBind := range existingBinds {
			if existingBind.Name == QUIC4BIND {
				bindIPv4Exists = true
			}
			if existingBind.Name == QUIC6BIND {
				bindIPv6Exists = true
			}
		}
	}

	addBind := func(addr string, bindName string, v4v6 bool) {
		binds = append(binds, models.Bind{
			Address: addr,
			Port:    utils.PtrInt64(q.QuicBindPort),
			BindParams: models.BindParams{
				Name:           bindName,
				Ssl:            true,
				SslCertificate: q.CertDir,
				Alpn:           "h3",
				V4v6:           v4v6,
			},
		})
	}

	if q.IPv4 && !bindIPv4Exists {
		addBind("quic4@"+q.AddrIPv4, QUIC4BIND, false)
	}
	if q.IPv6 && !bindIPv6Exists {
		addBind("quic6@"+q.AddrIPv6, QUIC6BIND, true)
	}

	for _, bind := range binds {
		err = h.FrontendBindCreate(h.FrontHTTPS, bind)
		if err != nil {
			return err
		}
	}

	if len(binds) > 0 {
		instance.Reload("QUIC enabled")
	}
	return
}

func (q *Quic) disableQUIC(h haproxy.HAProxy) (err error) {
	errors := utils.Errors{}
	deleteBind := func(bindName string) (err error) {
		_, err = h.FrontendBindGet(h.FrontHTTPS, bindName)
		if err == nil {
			err = h.FrontendBindDelete(h.FrontHTTPS, bindName)
		}
		return
	}
	if q.IPv6 {
		errors.Add(deleteBind(QUIC6BIND))
	}
	if q.IPv4 {
		errors.Add(deleteBind(QUIC4BIND))
	}
	err = errors.Result()
	if err == nil {
		instance.Reload("QUIC disabled")
	}
	return
}

func (q *Quic) altSvcRule(h haproxy.HAProxy) (err error) {
	errors := utils.Errors{}
	logger.Debug("quic redirect rule to be created")
	errors.Add(h.AddRule(h.FrontHTTPS, rules.RequestRedirectQuic{}, false))
	logger.Debug("quic set header rule to be created")
	errors.Add(h.AddRule(h.FrontHTTPS, rules.SetHdr{
		HdrName:   "alt-svc",
		Response:  true,
		HdrFormat: fmt.Sprintf("\"h3=\\\":%d\\\"; ma="+q.MaxAge+"\"", q.QuicAnnouncePort),
	}, false))
	return errors.Result()
}

func (q *Quic) Update(k store.K8s, h haproxy.HAProxy, a annotations.Annotations) (err error) {
	if !q.Enabled {
		logger.Debug("Cannot proceed with QUIC update, it is disabled")
		return
	}

	// ssl-offload
	sslOffloadEnabled := h.FrontendSSLOffloadEnabled(h.FrontHTTPS)
	if !sslOffloadEnabled {
		logger.Warning("QUIC requires SSL offload to be enabled")
		logger.Error(q.disableQUIC(h))
		instance.Reload("QUIC disabled")
		return
	}

	maxAge := common.GetValue("quic-alt-svc-max-age", k.ConfigMaps.Main.Annotations)
	updatedMaxAge := maxAge != q.MaxAge
	if updatedMaxAge {
		instance.Reload("QUIC max age updated from %s to %s", q.MaxAge, maxAge)
		q.MaxAge = maxAge
	}

	nsSslCertificateAnn, nameSslCertificateAnn, err := common.GetK8sPath("ssl-certificate", k.ConfigMaps.Main.Annotations)
	if err != nil || (nameSslCertificateAnn == "") {
		logger.Error(q.disableQUIC(h))
		return
	} else {
		namespaceSslCertificate := k.Namespaces[nsSslCertificateAnn]
		var sslSecret *store.Secret
		if namespaceSslCertificate != nil {
			sslSecret = namespaceSslCertificate.Secret[nameSslCertificateAnn]
		}

		if sslSecret == nil || sslSecret.Status == store.DELETED {
			logger.Error(q.disableQUIC(h))
			return
		} else {
			logger.Error(q.enableQUIC(h))
		}
	}

	return
}
