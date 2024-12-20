## Envoy mTLS and JWT Auth with RBAC

Sample envoy configurations that shows [RBAC](https://www.envoyproxy.io/docs/envoy/latest/api-v2/config/rbac/v2/rbac.proto#config-rbac-v2-rbac) rules derived from certificate and JWT based auth.  

- For mTLS, Envoy will parse the provided certificate from the client, extract its `Subject Alternative Name` and then evaluate it against RBAC rules

- For JWT, Envoy will parse the provided JWT header value from the client, extract its `Subject (sub)` claim and then evaluate it against RBAC rules.

In both cases, the RBAC rules will also check for a custom header value: `Header:  User: sal`


### Setup

Get envoy however you want


```bash
docker cp `docker create envoyproxy/envoy-dev:latest`:/usr/local/bin/envoy .
```

### JWT

First configure [https://github.com/envoyproxy/envoy/blob/master/api/envoy/extensions/filters/http/jwt_authn/v3/config.proto](jwt_authn) in istio to do several things:

```yaml
          - name: envoy.filters.http.jwt_authn
            typed_config:
              "@type": type.googleapis.com/envoy.config.filter.http.jwt_authn.v2alpha.JwtAuthentication
              providers:          
                google-jwt:
                  issuer: testing@secure.istio.io
                  payload_in_metadata: "my_payload"
                  remote_jwks:
                    http_uri:
                      uri: https://raw.githubusercontent.com/istio/istio/release-1.7/security/tools/jwt/samples/jwks.json
                      cluster: jwt.raw.githubusercontent.com|443
                      timeout: 5s
                  from_headers:
                  - name: Authorization
                    value_prefix: "Bearer "
              rules:
              - match:
                  prefix: "/"
                requires:
                  provider_name: "google-jwt"      
```

- decode the inbound JWT arriving as the `Authorization:` header value
- download and cache the verification certificates for the JWT at the `remote_jwks` uri
- verify the decoded JWT was issued by `testing@secure.istio.io`
- emit all the claims in the JWT as [dynamic metadata](https://www.envoyproxy.io/docs/envoy/latest/api-v2/type/matcher/metadata.proto#) for another filter to use with the label `my_payload`.  This step is important!

Note, the [istio demo jwt](https://raw.githubusercontent.com/istio/istio/release-1.7/security/tools/jwt/samples/demo.jwt) includes the following claims:

```json
{
  "alg": "RS256",
  "kid": "DHFbpoIUqrY8t2zpA2qXfCmr5VO5ZEr4RzHU_-envvQ",
  "typ": "JWT"
}.
{
  "exp": 4685989700,
  "foo": "bar",
  "iat": 1532389700,
  "iss": "testing@secure.istio.io",
  "sub": "testing@secure.istio.io"
}
```


Run Envoy:

```bash
envoy -c envoy-conf-jwt.yaml -l trace
```

Invoke Envoy with static JWT:

```bash
export TOKEN=`curl -s https://raw.githubusercontent.com/istio/istio/release-1.7/security/tools/jwt/samples/demo.jwt`

curl -v -H "host: http.domain.com"  --resolve  http.domain.com:8080:127.0.0.1 \
  --cacert certs/root-ca.crt \
  -H "Authorization: Bearer $TOKEN" \
  -H "User: sal" https://http.domain.com:8080/get
```


Note the JWT verification succeeded, then the dynamic metadata was emitted back out for the RBAC filter to consume:

```log
[2020-10-23 07:53:17.114][43705][debug][jwt] [external/envoy/source/extensions/filters/http/jwt_authn/authenticator.cc:267] google-jwt: JWT token verification completed with: OK
[2020-10-23 07:53:17.114][43705][debug][jwt] [external/envoy/source/extensions/filters/http/jwt_authn/filter.cc:87] Called Filter : check complete OK


[2020-10-23 07:53:17.114][43705][debug][rbac] [external/envoy/source/extensions/filters/http/rbac/rbac_filter.cc:74] checking request: requestedServerName: , sourceIP: 127.0.0.1:45188, directRemoteIP: 127.0.0.1:45188, remoteIP: 127.0.0.1:45188,localAddress: 127.0.0.1:8080, ssl: uriSanPeerCertificate: , dnsSanPeerCertificate: , subjectPeerCertificate: , headers: ':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
'user-agent', 'curl/7.72.0'
'accept', '*/*'
'user', 'sal'
'x-forwarded-proto', 'https'
'x-request-id', '3e7cc4d2-2125-4e66-90d9-fc510280f8cd'
, dynamicMetadata: filter_metadata {
  key: "envoy.filters.http.jwt_authn"
  value {
    fields {
      key: "my_payload"
      value {
        struct_value {
          fields {
            key: "exp"
            value {
              number_value: 4685989700
            }
          }
          fields {
            key: "foo"
            value {
              string_value: "bar"
            }
          }
          fields {
            key: "iat"
            value {
              number_value: 1532389700
            }
          }
          fields {
            key: "iss"
            value {
              string_value: "testing@secure.istio.io"
            }
          }
          fields {
            key: "sub"
            value {
              string_value: "testing@secure.istio.io"
            }
          }
        }
      }
    }
  }
}

[2020-10-23 07:53:17.114][43705][debug][rbac] [external/envoy/source/extensions/filters/http/rbac/rbac_filter.cc:113] enforced allowed
```

In the case above, the RBAC filter read in values present in metadata under namespace key `my_payload` and key `sub`.  This was a bit confusing to me because the order top-down of the `principals.metadata.path` in the config actually maps back in the hierarchy order

from jwt_authn:

```
dynamicMetadata: filter_metadata {
  key: "envoy.filters.http.jwt_authn"
  value {
    fields {
      key: "my_payload"
        fields {
            key: "sub"
            value {
              string_value: "testing@secure.istio.io"
            }
```

rbac config

```yaml
- name: envoy.filters.http.rbac 
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC       
    rules: 
      action: ALLOW
      policies:
        "allow-sub-match-rule":
          permissions:
          - and_rules:
              rules:
              - header: { name: ":method", exact_match: "GET" }
              - header: { name: "User", exact_match: "sal" }
              - url_path:
                  path: { prefix: "/" }
          principals:                 
          - metadata:
              filter: envoy.filters.http.jwt_authn
              path:
                - key: my_payload
                - key: sub
              value:
                string_match:
                  exact:  "testing@secure.istio.io"  
```

At this point, change any of the values (method, user header, or subject field in the RBAC or JWT config)

The first rule that is hit is the JWT authn so if you don't send over a valid JWT, you won't even get authenticated.

If you send a valid JWT, then the RBAC rules pick up.  If you change the setting in your request or in the RBAC config, you should see an RBAC error while making the request


### mTLS

This section uses fields extracted from an[envoy mTLS](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ssl) connection for RBAC rules.

First note the specifications of the certs contained in this repo:

- Client certificate

Has a `X509v3 Subject Alternative Name:` value of  `DNS:client.domain.com`
Envoy's RBAC filter only looks for DNS or IP SAN.  For some reason, it doesn't use EMAIL (i suppose its because thats not used in svc->svc mode)

```bash
openssl x509 -in client-svc.crt -noout -text

      Certificate:
          Data:
              Version: 3 (0x2)
              Serial Number: 27 (0x1b)
              Signature Algorithm: sha256WithRSAEncryption
              Issuer: C=US, O=Google, OU=Enterprise, CN=Single Root CA
              Validity
                  Not Before: Jun 11 11:27:52 2024 GMT
                  Not After : Jun 11 11:27:52 2034 GMT
              Subject: L=US, O=Google, OU=Enterprise, CN=client.domain.com


        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                8F:4F:66:D1:B5:1A:B7:68:C2:CA:88:EB:8D:11:8B:87:C7:0B:41:9A
            X509v3 Authority Key Identifier: 
                EC:F0:EA:53:53:3F:9F:23:DC:C1:0E:31:10:37:07:DE:DE:E7:6E:F3
            Authority Information Access: 
                CA Issuers - URI:http://pki.esodemoapp2.com/ca/root-ca.cer
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:http://pki.esodemoapp2.com/ca/root-ca.crl
            X509v3 Subject Alternative Name: 
                DNS:client.domain.com


```

- Server certificate

Its a standard cert configured for DNS SAN `DNS:http.domain.com`
```bash
openssl x509 -in server.crt -noout -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 7 (0x7)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Google, OU=Enterprise, CN=Single Root CA
        Validity
            Not Before: Mar 29 19:06:50 2024 GMT
            Not After : Mar 29 19:06:50 2034 GMT
        Subject: C=US, O=Google, OU=Enterprise, CN=http.domain.com

        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Subject Key Identifier: 
                1D:6A:C1:70:D6:6B:44:B5:DC:79:AD:76:A6:23:BB:FA:2D:12:3F:C1
            X509v3 Authority Key Identifier: 
                EC:F0:EA:53:53:3F:9F:23:DC:C1:0E:31:10:37:07:DE:DE:E7:6E:F3
            Authority Information Access: 
                CA Issuers - URI:http://pki.esodemoapp2.com/ca/root-ca.cer
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:http://pki.esodemoapp2.com/ca/root-ca.crl
            X509v3 Subject Alternative Name: 
                DNS:http.domain.com
```

You can generate and use your own certs with a sample CA [here](https://github.com/salrashid123/ca_scratchpad)


Anyway Run envoy

```bash
envoy -c envoy-conf-tls.yaml -l trace
```

Run Client

```bash
curl -v -H "host: http.domain.com"  \
   --resolve  http.domain.com:8080:127.0.0.1 \
   --cacert certs/root-ca.crt --cert certs/client-svc.crt --key certs/client-svc.key \
   -H "User: sal" https://http.domain.com:8080/get
```


Note the Envoy log  negotiated the TLS connection and then extracted out the certificate specifications:

```log
[2024-11-16 07:54:32.201][34474][debug][rbac] [source/extensions/filters/http/rbac/rbac_filter.cc:161] checking request: requestedServerName: , sourceIP: 127.0.0.1:48402, directRemoteIP: 127.0.0.1:48402, remoteIP: 127.0.0.1:48402,localAddress: 127.0.0.1:8080, ssl: uriSanPeerCertificate: , dnsSanPeerCertificate: client.domain.com, subjectPeerCertificate: CN=client.domain.com,OU=Enterprise,O=Google,L=US, headers: ':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
':scheme', 'https'
'user-agent', 'curl/8.8.0'
'accept', '*/*'
'user', 'sal'
'x-forwarded-proto', 'https'
'x-request-id', '9930b0f3-e0d3-43af-9191-7d5139003abc'
, dynamicMetadata: 
[2024-11-16 07:54:32.201][34474][debug][rbac] [source/extensions/filters/http/rbac/rbac_filter.cc:212] enforced allowed, matched policy allow-sub-match-rule
```


eg
```log
[2020-10-23 08:07:38.134][45831][debug][rbac] [external/envoy/source/extensions/filters/http/rbac/rbac_filter.cc:74] checking request: requestedServerName: , sourceIP: 127.0.0.1:45704, directRemoteIP: 127.0.0.1:45704, remoteIP: 127.0.0.1:45704,localAddress: 127.0.0.1:8080, ssl: uriSanPeerCertificate: , dnsSanPeerCertificate: client-svc.domain.com, subjectPeerCertificate: CN=client-svc@domain.com,OU=Enterprise,O=Google,C=US, headers: ':authority', 'http.domain.com'
```

At that point the RBAC module uses the `dnsSanPeerCertificate` value of `client-svc.domain.com` in its rule to validate the inbound conn.

You can alter the value in the envoy config to test out failure modes, etc.

Thats all folks.
