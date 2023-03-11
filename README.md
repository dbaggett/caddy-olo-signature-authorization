# Caddy OLO Signature Authorization
Generates the [OLO](https://www.olo.com/) Authorization header required for server-to-server integration with [OLO's Ordering API](https://www.olo.com/ordering).

## Details
OLO requires several headers to be sent on all requests - one of them being a _meticulously_ formatted Authorization header. This module handles the following:
* Adds the `Authorization` header to the request
* Adds the `Date` header
* Adds the `X-Forwarded-For` header __*__

---

The `X-Forwarded-For` header will only be added when __not__ provided by the client. It's recommended for the client to provide the  `X-Forwarded-For` header.

---

## Configuration
```
olo_signature {
  client_id test
  client_secret test
}
```

You may need to specify ordering globally like so:
```
{
  order olo_signature first
}
```

## Why This Exists
TLDR; OLO requires all requests originating from a web-based client to pass through a proxy - server-to-server.

OLO refers to this mode of authorization as `Signature Authorization`. See how the outbound `Authorization` header is generated [here](#authorization).

## Headers
For readers to know they're in the right place, below is a regurgitation of OLO documentation for required headers. All of these are handled by this module.

### Date
Current timestamp in RFC1123 format using a fixed GMT offset.

### Authorization
Format - `OloSignature {ClientId}:{Signature}`

Signature (quasi-)pseudo-code:
```go
components := []string{
  olo.ClientId,
	request.Method,
	request.Header.Get("Content-Type"),
	base64.StdEncoding.EncodeToString(sha256HashedBody),
	request.URL.RequestURI(),
	requestDate,
}

hmacSha256([]byte(strings.Join(components, "\n")))

signature = base64.StdEncoding.EncodeToString(encryptedComponents)
```
