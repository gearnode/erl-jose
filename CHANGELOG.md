# Introduction
All notable changes to this project will be documented in this file.

The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Add `jose_jws:supported_crits/0` function.
- Add JWK decoding.
- Add JWK to Erlang records.

## Changed
- Extract base64 encoding modules in dedicated library.
- Rename `jose_jwa:verify/4` in `jose_jwa:is_valid/4`.
- Reformat the codebase.
- Remove deprecated hex dependency.

### Fixed
- Fix media type without type returns an error.
- Fix handling of unknown gen_server calls.
- Support x5t with hex value instead of byte.

## [0.1.0] (2021-01-18)
### Added
- Add JWA HMAC with SHA2 algorithms
- Add JWA RSASSA-PKCS1-v1_5 algorithms
- Add JWA ECDSA algorithms
- Add JOSE media type header parameter name encoding and decoding
- Add trusted certificate store
- Add trusted key store
- Add JWS compact encode
- Add JWS compact decode
- Add JWS non base64 encoded payload
- Add JWT encode
- Add JWT decode
