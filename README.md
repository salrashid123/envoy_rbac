## Envoy mTLS and JWT Auth with RBAC

Sample envoy configurations that shows [RBAC](https://www.envoyproxy.io/docs/envoy/latest/api-v2/config/rbac/v2/rbac.proto#config-rbac-v2-rbac) rules derived from certificate and JWT based auth.  

- For mTLS, Envoy will parse the provided certificate from the client, extract its `Subject Alternative Name` and then evaluate it against RBAC rules

- For JWT, Envoy will parse the provided JWT header value from the client, extract its `Subject (sub)` claim and then evaluate it against RBAC rules.

In both cases, the RBAC rules will also check for a custom header value: `Header:  User: sal`


### Setup

Get envoy however you want

```bash
docker cp `docker create envoyproxy/envoy:v1.14.3`:/usr/local/bin/envoy .
```

### JWT

First configure [https://www.envoyproxy.io/docs/envoy/latest/api-v2/config/filter/http/jwt_authn/v2alpha/config.proto](jwt_authn) in istio to do several things:

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
            timeout:
              seconds: 5                      
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
  --cacert certs/tls-ca.crt \
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

Has a `X509v3 Subject Alternative Name:` value of  `DNS:client-svc.domain.com`
Envoy's RBAC filter only looks for DNS or IP SAN.  For some reason, it doesn't use EMAIL (i suppose its because thats not used in svc->svc mode)

```bash
openssl x509 -in client-svc.crt -noout -text

    Certificate:
        Data:
            Version: 3 (0x2)
            Serial Number: 10 (0xa)
            Signature Algorithm: sha1WithRSAEncryption
            Issuer: C = US, O = Google, OU = Enterprise, CN = Enterprise Subordinate CA
            Validity
                Not Before: Oct 23 02:37:24 2020 GMT
                Not After : Oct 23 02:37:24 2022 GMT
            Subject: C = US, O = Google, OU = Enterprise, CN = client-svc@domain.com

        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Alternative Name: 
                DNS:client-svc.domain.com

```

- Server certificate

Its a standard cert configured for DNS SAN `DNS:http.domain.com`
```bash
openssl x509 -in server.crt -noout -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 7 (0x7)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C = US, O = Google, OU = Enterprise, CN = Enterprise Subordinate CA
        Validity
            Not Before: Jul 10 19:29:07 2020 GMT
            Not After : Jul 10 19:29:07 2022 GMT
        Subject: C = US, O = Google, OU = Enterprise, CN = http.domain.com

        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Subject Alternative Name: 
                DNS:http.domain.com
```

You can generate and use your own certs with a sample CA [here](https://github.com/salrashid123/ca_scratchpad)


Anyway Run envoy

```
envoy -c envoy-conf-tls.yaml -l trace
```

Run Client

```bash
curl -v -H "host: http.domain.com"  \
   --resolve  http.domain.com:8080:127.0.0.1 \
   --cacert certs/tls-ca.crt --cert certs/client-svc.crt --key certs/client-svc.key \
   -H "User: sal" https://http.domain.com:8080/get
```


Note the Envoy log  negotiated the TLS connection and then extracted out the certificate specifications:

```log
[2020-10-23 08:07:38.109][45831][debug][conn_handler] [external/envoy/source/server/connection_handler_impl.cc:422] [C0] new connection
[2020-10-23 08:07:38.109][45831][trace][connection] [external/envoy/source/common/network/connection_impl.cc:506] [C0] socket event: 2
[2020-10-23 08:07:38.109][45831][trace][connection] [external/envoy/source/common/network/connection_impl.cc:607] [C0] write ready
[2020-10-23 08:07:38.109][45831][debug][connection] [external/envoy/source/extensions/transport_sockets/tls/ssl_socket.cc:190] [C0] handshake expecting read
[2020-10-23 08:07:38.119][45831][trace][connection] [external/envoy/source/common/network/connection_impl.cc:506] [C0] socket event: 3
[2020-10-23 08:07:38.119][45831][trace][connection] [external/envoy/source/common/network/connection_impl.cc:607] [C0] write ready
[2020-10-23 08:07:38.125][45831][debug][connection] [external/envoy/source/extensions/transport_sockets/tls/ssl_socket.cc:190] [C0] handshake expecting read
[2020-10-23 08:07:38.125][45831][trace][connection] [external/envoy/source/common/network/connection_impl.cc:544] [C0] read ready. dispatch_buffered_data=false
[2020-10-23 08:07:38.125][45831][debug][connection] [external/envoy/source/extensions/transport_sockets/tls/ssl_socket.cc:190] [C0] handshake expecting read
[2020-10-23 08:07:38.131][45831][trace][connection] [external/envoy/source/common/network/connection_impl.cc:506] [C0] socket event: 3
[2020-10-23 08:07:38.131][45831][trace][connection] [external/envoy/source/common/network/connection_impl.cc:607] [C0] write ready
[2020-10-23 08:07:38.133][45831][debug][connection] [external/envoy/source/extensions/transport_sockets/tls/ssl_socket.cc:175] [C0] handshake complete
[2020-10-23 08:07:38.133][45831][trace][connection] [external/envoy/source/common/network/connection_impl.cc:544] [C0] read ready. dispatch_buffered_data=false
[2020-10-23 08:07:38.133][45831][trace][connection] [external/envoy/source/extensions/transport_sockets/tls/ssl_socket.cc:80] [C0] ssl read returns: 93
[2020-10-23 08:07:38.133][45831][trace][connection] [external/envoy/source/extensions/transport_sockets/tls/ssl_socket.cc:80] [C0] ssl read returns: -1
[2020-10-23 08:07:38.133][45831][trace][connection] [external/envoy/source/extensions/transport_sockets/tls/ssl_socket.cc:154] [C0] ssl read 93 bytes
[2020-10-23 08:07:38.133][45831][trace][http] [external/envoy/source/common/http/http1/codec_impl.cc:543] [C0] parsing 93 bytes
[2020-10-23 08:07:38.133][45831][trace][http] [external/envoy/source/common/http/http1/codec_impl.cc:756] [C0] message begin
[2020-10-23 08:07:38.133][45831][debug][http] [external/envoy/source/common/http/conn_manager_impl.cc:261] [C0] new stream
[2020-10-23 08:07:38.134][45831][trace][http] [external/envoy/source/common/http/http1/codec_impl.cc:478] [C0] completed header: key=Host value=http.domain.com
[2020-10-23 08:07:38.134][45831][trace][http] [external/envoy/source/common/http/http1/codec_impl.cc:478] [C0] completed header: key=User-Agent value=curl/7.72.0
[2020-10-23 08:07:38.134][45831][trace][http] [external/envoy/source/common/http/http1/codec_impl.cc:478] [C0] completed header: key=Accept value=*/*
[2020-10-23 08:07:38.134][45831][trace][http] [external/envoy/source/common/http/http1/codec_impl.cc:642] [C0] onHeadersCompleteBase
[2020-10-23 08:07:38.134][45831][trace][http] [external/envoy/source/common/http/http1/codec_impl.cc:478] [C0] completed header: key=User value=sal
[2020-10-23 08:07:38.134][45831][trace][http] [external/envoy/source/common/http/http1/codec_impl.cc:862] [C0] Server: onHeadersComplete size=4
[2020-10-23 08:07:38.134][45831][trace][http] [external/envoy/source/common/http/http1/codec_impl.cc:733] [C0] message complete
[2020-10-23 08:07:38.134][45831][trace][connection] [external/envoy/source/common/network/connection_impl.cc:315] [C0] readDisable: disable=true disable_count=0 state=0 buffer_length=93
[2020-10-23 08:07:38.134][45831][debug][http] [external/envoy/source/common/http/conn_manager_impl.cc:808] [C0][S2535252511564349998] request headers complete (end_stream=true):
':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
'user-agent', 'curl/7.72.0'
'accept', '*/*'
'user', 'sal'
[2020-10-23 08:07:38.134][45831][debug][http] [external/envoy/source/common/http/conn_manager_impl.cc:1377] [C0][S2535252511564349998] request end stream


[2020-10-23 08:07:38.134][45831][debug][rbac] [external/envoy/source/extensions/filters/http/rbac/rbac_filter.cc:74] checking request: requestedServerName: , sourceIP: 127.0.0.1:45704, directRemoteIP: 127.0.0.1:45704, remoteIP: 127.0.0.1:45704,localAddress: 127.0.0.1:8080, ssl: uriSanPeerCertificate: , dnsSanPeerCertificate: client-svc.domain.com, subjectPeerCertificate: CN=client-svc@domain.com,OU=Enterprise,O=Google,C=US, headers: ':authority', 'http.domain.com'
':path', '/get'
':method', 'GET'
'user-agent', 'curl/7.72.0'
'accept', '*/*'
'user', 'sal'
'x-forwarded-proto', 'https'
'x-request-id', '0f2fc3a2-bc5f-4930-a822-8f9d361ad540'
, dynamicMetadata: 


[2020-10-23 08:07:38.134][45831][debug][rbac] [external/envoy/source/extensions/filters/http/rbac/rbac_filter.cc:113] enforced allowed

```


eg
```log
[2020-10-23 08:07:38.134][45831][debug][rbac] [external/envoy/source/extensions/filters/http/rbac/rbac_filter.cc:74] checking request: requestedServerName: , sourceIP: 127.0.0.1:45704, directRemoteIP: 127.0.0.1:45704, remoteIP: 127.0.0.1:45704,localAddress: 127.0.0.1:8080, ssl: uriSanPeerCertificate: , dnsSanPeerCertificate: client-svc.domain.com, subjectPeerCertificate: CN=client-svc@domain.com,OU=Enterprise,O=Google,C=US, headers: ':authority', 'http.domain.com'
```

At that point the RBAC module uses the `dnsSanPeerCertificate` value of `client-svc.domain.com` in its rule to validate the inbound conn.

You can alter the value in the envoy config to test out failure modes, etc.

Thats all folks.
