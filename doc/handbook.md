# Introduction
This repository contains development notes about the `erl-jose` library.

# Versioning
The following `jose` versions are available:
- `0.y.z` unstable versions.
- `x.y.z` stable versions: `jose` will maintain reasonable backward
  compatibility, deprecating features before removing them.
- Experimental untagged versions.

Developers who use unstable or experimental versions are responsible for
updating their application when `jose` is modified. Note that unstable
versions can be modified without backward compatibility at any time.

# Terminology
These terms are used by this documentation:
- **JSON Web Signature (JWS):** A data structure representing a digitally signed
  or MACed message.
- **JOSE Header:** JSON object containing the parameters describing the
  cryptographic operations and parameters employed.
- **JWS Payload:** The sequence of octets to be secured. The payload can contain
  an arbitrary sequence of octets.
- **JWS Signature:** Digital signature or MAC over the JWS Protected Header and
  the JWS Payload.
- **Header Parameter:** A name/value pair that is member of the JOSE Header.

These term are defined by the documentation:
- **Certificate store:** A database that store certificate to make trust decision
  when decoding JWS.

# JSON Web Signature (JWS)
## Supported algorithms
The lable below describe the supported signature algorithms:
| "alg" param value | Digital signature or MAC algorithms            | Supported |
|-------------------|------------------------------------------------|-----------|
| HS256             | HMAC using SHA-256                             | YES       |
| HS384             | HMAC using SHA-384                             | YES       |
| HS512             | HMAC using SHA-512                             | YES       |
| RS256             | RSASSA-PKCS1-v1_5 using SHA-256                | YES       |
| RS384             | RSASSA-PKCS1-v1_5 using SHA-384                | YES       |
| RS512             | RSASSA-PKCS1-v1_5 using SHA-512                | YES       |
| ES256             | ECDSA using P-256 and SHA-256                  | YES       |
| ES384             | ECDSA using P-384 and SHA-384                  | YES       |
| ES512             | ECDSA using P-521 and SHA-512                  | YES       |
| PS256             | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 | NO        |
| PS384             | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 | NO        |
| PS512             | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 | NO        |
| none              | No digital signature or MAC performed          | YES       |

Only algorithms used by Exograd are implemented at this moment, there is not
plan to support more algorithms at the moment.

## Encode
### Compact
Encode JWS in compact format can be done with:
```erlang
Header = #{alg => hs256},
Payload = <<"signed message">>,
Key = <<"secret key">>,
jose_jws:encode_compact(Header, Payload, hs256, Key).
```

### JSON
The JSON format is currently not supported.

### Flattened JSON
The Flattened JSON format is currently not supported.

# Certificate store
Certificate store is used to decode JWS, JWE or valid a JWK in order to make a
trust decision.

The certificate store can be populate with certificates at the application
startup with the configuration:
```erlang
[{jose,
    [{certificate_store,
        #{file => ["/path/of/the/certificate.crt",
                   "/path/of/other/certficiate.pem"]}}]}]
```
The certificate file **MUST** be a PEM encoded file and **MAY** be a
certificate bundle.

Add certificate in the store with:
```erlang
ok = jose_certificate_store:add(jose_certificate_store, Der}.
```

Or remove certificate in the store:
```erlang
ok = jose_certificate_store:remove(jose_certificate_store, Der).
```
