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
