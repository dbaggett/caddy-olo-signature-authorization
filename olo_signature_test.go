package olosignature

import (
	"net/http"
	"net/url"
	"testing"
)

func testDate() string {
	return "Fri, 24 Feb 2023 18:16:42 GMT"
}

func TestGenerateOloSignatureHeadersExists(t *testing.T) {
    url, _ := url.Parse("http://localhost/test/path?key=value&key=value")

    request := &http.Request {
        Method: "GET",
        URL: url,
        Body: nil,
        Header: make(http.Header),
    }

		oloCredentials := NewOloCredentials("test", "test")

    signatureError := oloCredentials.generateOloSignature(request)

    if signatureError != nil {
        t.Fatal(signatureError)
    }

    if request.Header.Get("Authorization") == "" {
        t.Error("Authorization header was not generated")
    }

		if request.Header.Get("Date") == "" {
			t.Error("Date header was not generated")
	}
}

func TestGenerateOloSignatureGeneration(t *testing.T) {
    url, _ := url.Parse("http://localhost/test/path?key=value&key=value")

    request := &http.Request {
        Method: "GET",
        URL: url,
        Body: nil,
        Header: make(http.Header),
    }

    oloCredentials := OloCredentials {
			ClientId: "test",
			ClientSecret: "test",
			currentDateTimeStamp: testDate,
		}

    signatureError := oloCredentials.generateOloSignature(request)

    if signatureError != nil {
        t.Fatal(signatureError)
    }

    println(request.Header.Get("Authorization"))

    if request.Header.Get("Authorization") != "OloSignature test:0+FbRN6W75XYnFZwY6/6h8qPQHwCaL0pmRYypVimOzY=" {
        t.Error("Authorization header was not generated")
    }
}