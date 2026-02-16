package ingress

import (
	"fmt"
	"strconv"

	"github.com/haproxytech/kubernetes-ingress/pkg/annotations/common"
	"github.com/haproxytech/kubernetes-ingress/pkg/haproxy/rules"
	"github.com/haproxytech/kubernetes-ingress/pkg/store"
	"github.com/haproxytech/kubernetes-ingress/pkg/utils"
)

type HTTPSRedirect struct {
	redirect *rules.RequestRedirect
	rules    *rules.List
	ingress  *store.Ingress
}

type HTTPSRedirectAnn struct {
	parent *HTTPSRedirect
	name   string
}

func NewHTTPSRedirect(rules *rules.List, i *store.Ingress) *HTTPSRedirect {
	return &HTTPSRedirect{rules: rules, ingress: i}
}

func (p *HTTPSRedirect) NewAnnotation(n string) HTTPSRedirectAnn {
	return HTTPSRedirectAnn{
		name:   n,
		parent: p,
	}
}

func (a HTTPSRedirectAnn) GetName() string {
	return a.name
}

func (a HTTPSRedirectAnn) Process(k store.K8s, annotations ...map[string]string) error {
	input := common.GetValue(a.GetName(), annotations...)
	if input == "" {
		if a.name == "ssl-redirect" && tlsEnabled(a.parent.ingress) {
			// Enable HTTPS redirect automatically when ingress resource has TLS secrets
			a.parent.redirect = &rules.RequestRedirect{SSLRedirect: true}
			a.parent.rules.Add(a.parent.redirect)
		}
		return nil
	}

	switch a.name {
	case "ssl-redirect":
		enable, errBool := utils.GetBoolValue(input, "ssl-redirect")
		if errBool != nil {
			return errBool
		}
		if !enable {
			return nil
		}
		// Enable HTTPS redirect
		a.parent.redirect = &rules.RequestRedirect{SSLRedirect: true}
		a.parent.rules.Add(a.parent.redirect)
		return nil
	case "ssl-redirect-port":
		if a.parent.redirect == nil {
			return nil
		}
		port, err := strconv.Atoi(input)
		if err != nil {
			return err
		}
		a.parent.redirect.RedirectPort = port
	case "ssl-redirect-code":
		if a.parent.redirect == nil {
			return nil
		}
		code, err := strconv.ParseInt(input, 10, 64)
		if err != nil {
			return err
		}
		a.parent.redirect.RedirectCode = code
	default:
		return fmt.Errorf("unknown ssl-redirect annotation '%s'", a.name)
	}
	return nil
}

func tlsEnabled(ingress *store.Ingress) bool {
	if ingress == nil {
		return false
	}
	if len(ingress.TLS) == 0 {
		return false
	}
	return true
}
