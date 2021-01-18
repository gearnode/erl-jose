# Introduction
All notable changes to this project will be documented in this file.

The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Add `jose_jws:supported_crits/0` function.

### Fixed
- Fix media type without type returns an error.

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
