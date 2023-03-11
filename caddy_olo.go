package olosignature

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
		caddy.RegisterModule(OloSignature{})
  	httpcaddyfile.RegisterHandlerDirective("olo_signature", parseCaddyfile)
}

type OloSignature struct {
		ClientId string `json:"client_id,omitempty"`
		ClientSecret string `json:"client_secret,omitempty"`

		oloCredentials OloCredentials
}

func (OloSignature) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID: "http.handlers.olo_signature",
        New: func() caddy.Module { return new(OloSignature) },
    }
}

func (m *OloSignature) Provision(ctx caddy.Context) error {
    m.oloCredentials = NewOloCredentials(m.ClientId, m.ClientSecret)

    return nil
}

func (m OloSignature) Validate() error {
    if m.ClientId == ""  {
        return fmt.Errorf("missing client_id as required by olo signature authorization, check your Caddyfile and read the docs")
    }

		if m.ClientSecret == ""  {
			return fmt.Errorf("missing client_secret as required by olo signature authorization, check your Caddyfile and read the docs")
		}

    return nil
}

func (m OloSignature) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
    m.oloCredentials.generateOloSignature(r)
		
    return next.ServeHTTP(w, r)
}

func (m *OloSignature) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
    for d.Next() {
        for d.NextBlock(0) {
            switch d.Val() {
                case "client_id":
                        if !d.Args(&m.ClientId) {
                            return d.ArgErr()
                        }
                case "client_secret":
                        if !d.Args(&m.ClientSecret) {
                            return d.ArgErr()
                        }
                default:
                        return d.Errf("unrecognized OLO signature directive '%s'", d.Val())
            }
        }
    }

		return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
    var olo OloSignature

    err := olo.UnmarshalCaddyfile(h.Dispenser)

    return olo, err
}

var (
	_ caddy.Provisioner           = (*OloSignature)(nil)
	_ caddy.Validator             = (*OloSignature)(nil)
	_ caddyhttp.MiddlewareHandler = (*OloSignature)(nil)
  _ caddyfile.Unmarshaler       = (*OloSignature)(nil)
)