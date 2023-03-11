package olosignature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type OloCredentials struct {
		ClientId string
		ClientSecret string

		currentDateTimeStamp func() string
}

func NewOloCredentials(clientId string, clientSecret string) OloCredentials {
		return OloCredentials{
			ClientId: clientId,
			ClientSecret: clientSecret,
			currentDateTimeStamp: currentDateTimeStamp,
		}
}

func currentDateTimeStamp() string {
		location := time.FixedZone("GMT", 0)
	
		return time.Now().In(location).Format(time.RFC1123)
}

func (olo OloCredentials) generateOloSignature(request *http.Request) error {
		hasher := sha256.New()

		if request.Body != nil {
			bytes, bodyError := io.ReadAll(request.Body)

			if bodyError != nil {
				return fmt.Errorf("error reading request body")
			}

			hasher.Write(bytes)
		} else {
			hasher.Write([]byte(""))
		}

		encyptor := hmac.New(sha256.New, []byte(olo.ClientSecret))

		requestDate := olo.currentDateTimeStamp()

		components := []string{
			olo.ClientId,
			request.Method,
			request.Header.Get("Content-Type"),
			base64.StdEncoding.EncodeToString(hasher.Sum(nil)),
			request.URL.RequestURI(),
			requestDate,
		}

		encyptor.Write([]byte(strings.Join(components, "\n")))

		request.Header.Set("Authorization", fmt.Sprintf("OloSignature %s:%s", olo.ClientId, base64.StdEncoding.EncodeToString(encyptor.Sum(nil))))
		request.Header.Set("Date", requestDate)

		return nil
}