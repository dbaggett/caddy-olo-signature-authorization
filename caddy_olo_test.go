package olosignature

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

type UpstreamHandler struct{}

func (UpstreamHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
    if r.Header.Get("Authorization") == "" {
      w.WriteHeader(http.StatusUnauthorized)
    } else {
      w.WriteHeader(http.StatusOK)
    }
	  
	  return nil
}

func TestAuthoizationHeaderSet(t *testing.T) {
    olo := OloSignature{
      ClientId: "test",
      ClientSecret: "test",
			oloCredentials: OloCredentials{
				ClientId: "test",
      	ClientSecret: "test",
				currentDateTimeStamp: func() string {
					return "Fri, 24 Feb 2023 18:16:42 GMT"
				},
			},
    }

    if err := olo.Provision(caddy.Context{}); err != nil {
      t.Fatalf("could not provision module: %v", err)
    }

    if err := olo.Validate(); err != nil {
      t.Fatalf("could not validate module: %v", err)
    }

    recorder := httptest.NewRecorder()
    request := httptest.NewRequest(http.MethodGet, "/basket", nil)

    if err := olo.ServeHTTP(recorder, request, UpstreamHandler{}); err != nil {
      t.Fatalf("serving HTTP failed: %v", err)
    }

    if recorder.Code != 200 {
      t.Fatalf("wrong response code: %d", recorder.Code)
    }

		if request.Header.Get("Authorization") == "" {
			t.Fatal("authorization header not set")
	}
}

func TestAuthoizationHeaderValid(t *testing.T) {
	olo := OloSignature{
		ClientId: "test",
		ClientSecret: "test",
		oloCredentials: OloCredentials{
			ClientId: "test",
			ClientSecret: "test",
			currentDateTimeStamp: func() string {
				return "Fri, 24 Feb 2023 18:16:42 GMT"
			},
		},
	}

	// skip provision step since it sets OloCredentials with current timestamp

	if err := olo.Validate(); err != nil {
		t.Fatalf("could not validate module: %v", err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/test/path?key=value&key=value", nil)

	if err := olo.ServeHTTP(recorder, request, UpstreamHandler{}); err != nil {
		t.Fatalf("serving HTTP failed: %v", err)
	}

	if recorder.Code != 200 {
		t.Fatalf("wrong response code: %d", recorder.Code)
	}

	if request.Header.Get("Authorization") != "OloSignature test:0+FbRN6W75XYnFZwY6/6h8qPQHwCaL0pmRYypVimOzY=" {
		t.Fatalf("not a valid OLO authorization header: %s", request.Header.Get("Authorization"))
}
}

func TestUnmarshallCaddyfileValid(t *testing.T) {
    directive := `olo_signature {
      client_id test
      client_secret test
    }`

    dispenser := caddyfile.NewTestDispenser(directive)

    olo := OloSignature{}

    if err := olo.UnmarshalCaddyfile(dispenser); err != nil {
        t.Fatalf("failed parsing Candyfile %v", err)
    }

    expected := OloSignature{
        ClientId: "test",
        ClientSecret: "test",
    }

    if !reflect.DeepEqual(olo, expected) {
        t.Fatal("unexpected subdirective")
    }
}

func TestParseCaddyfileValid(t *testing.T) {
  directive := `olo_signature {
    client_id test
    client_secret test
  }`

  dispenser := caddyfile.NewTestDispenser(directive)

  helper := httpcaddyfile.Helper{
    Dispenser: dispenser,
  }

  olo, err := parseCaddyfile(helper)

  if err != nil {
    t.Fatalf("failed parsing Candyfile %v", err)
  }

  expected := OloSignature{
    ClientId: "test",
    ClientSecret: "test",
  }

  if !reflect.DeepEqual(olo, expected) {
    t.Fatal("unexpected subdirective")
  }
}