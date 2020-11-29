# Introduction
This repository contains development notes about the `erl-jose` library.

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
