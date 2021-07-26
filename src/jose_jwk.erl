%% Copyright (c) 2020, 2021 Bryan Frimin <bryan@frimin.fr>.
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
%% SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
%% IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(jose_jwk).

-include_lib("public_key/include/public_key.hrl").

-export([decode/1, decode/2,
         to_record/1, from_record/1,
         from_certificate_chain/1]).

-export_type([jwk/0,
              rsa/0,
              ec/0,
              oct/0,
              type/0,
              use/0,
              key_ops/0,
              crv/0,
              coordinate/0,
              ecc_private_key/0,
              modulus/0,
              exponent/0,
              prime_factor/0,
              oth/0]).

-type jwk() :: oct() | rsa() | ec().

-type ec() :: ec_public() | ec_private().

-type ec_public() ::
        #{kty := 'EC',
          use => use(),
          key_ops => key_ops(),
          alg => jose_jwa:alg(),
          kid => jose:kid(),
          x5u => uri:uri(),
          x5c => [jose:certificate()],
          x5t => jose:certificate_thumbprint(),
          'x5t#S256' => jose:certificate_thumbprint(),
          crv := crv(),
          x := coordinate(),
          y => coordinate()}.

-type ec_private() :: 
        #{kty := 'EC',
          use => use(),
          key_ops => key_ops(),
          alg => jose_jwa:alg(),
          kid => jose:kid(),
          x5u => uri:uri(),
          x5c => [jose:certificate()],
          x5t => jose:certificate_thumbprint(),
          'x5t#S256' => jose:certificate_thumbprint(),
          crv := crv(),
          x := coordinate(),
          y => coordinate(),
          d := ecc_private_key()}.

-type rsa() :: rsa_public() | rsa_private().

-type rsa_public() ::
        #{kty := 'RSA',
          use => use(),
          key_ops => key_ops(),
          alg => jose_jwa:alg(),
          kid => jose:kid(),
          x5u => uri:uri(),
          x5c => [jose:certificate()],
          x5t => jose:certificate_thumbprint(),
          'x5t#S256' => jose:certificate_thumbprint(),
          n := modulus(),
          e := exponent()}.

-type rsa_private() ::
        #{kty := 'RSA',
          use => use(),
          key_ops => key_ops(),
          alg => jose_jwa:alg(),
          kid => jose:kid(),
          x5u => uri:uri(),
          x5c => [jose:certificate()],
          x5t => jose:certificate_thumbprint(),
          'x5t#S256' => jose:certificate_thumbprint(),
          n := modulus(),
          e := exponent(),
          d := exponent(),
          p => prime_factor(),
          q => prime_factor(),
          dp => exponent(),
          dq => exponent(),
          qi => non_neg_integer(),
          oth => [oth()]}.

-type oct() ::
        #{kty := oct,
          use => use(),
          key_ops => key_ops(),
          alg => jose_jwa:alg(),
          kid => jose:kid(),
          'x5t#S256' => jose:certificate_thumbprint(),
          k := binary()}.

% https://www.iana.org/assignments/jose/jose.xhtml#web-key-types
-type type() :: 'RSA' | 'EC' | oct.

% https://www.iana.org/assignments/jose/jose.xhtml#web-key-use
-type use() :: sig | enc.

-type key_ops() ::
        sign
      | verify
      | encrypt
      | decrypt
      | wrapKey
      | unwrapKey
      | deriveKey
      | deriveBits.

% https://www.iana.org/assignments/jose/jose.xhtml#web-key-elliptic-curve
-type crv() ::
        'P-256'
      | 'P-384'
      | 'P-521'.

-type coordinate() :: binary().
-type ecc_private_key() :: binary().
-type modulus() :: non_neg_integer().
-type exponent() :: non_neg_integer().
-type prime_factor() :: non_neg_integer().
-type oth() :: #{r := prime_factor(),
                 d := exponent(),
                 t := non_neg_integer()}.

-spec to_record(jwk()) -> term().
to_record(#{kty := 'RSA', n := N, e := E, d := D} = JWK) ->
  #'RSAPrivateKey'{version = 'two-prime',
                   modulus = N,
                   publicExponent = E,
                   privateExponent = D,
                   prime1 = maps:get(p, JWK, undefined),
                   prime2 = maps:get(q, JWK, undefined),
                   exponent1 = maps:get(dp, JWK, undefined),
                   exponent2 = maps:get(dq, JWK, undefined),
                   coefficient = maps:get(qi, JWK, undefined)};
to_record(#{kty := 'RSA', n := N, e := E}) ->
  #'RSAPublicKey'{modulus = N,
                  publicExponent = E};
to_record(#{kty := 'EC', crv := CRV, x := X, y := Y, d := D}) ->
  Curve =
    case CRV of
      'P-256' -> secp256r1;
      'P-384' -> secp384r1;
      'P-521' -> secp521r1
    end,
  #'ECPrivateKey'{version = 1,
                  privateKey = D,
                  parameters =
                    {namedCurve, pubkey_cert_records:namedCurves(Curve)},
                  publicKey = jose_crypto:ec_coordinate_to_point(X, Y)};
to_record(#{kty := 'EC', crv := CRV, x := X, y := Y}) ->
  Curve =
    case CRV of
      'P-256' -> secp256r1;
      'P-384' -> secp384r1;
      'P-521' -> secp521r1
    end,
  PublicKey = #'ECPoint'{point = jose_crypto:ec_coordinate_to_point(X, Y)},
  {PublicKey, {namedCurve, pubkey_cert_records:namedCurves(Curve)}};
to_record(#{kty := oct, k := K}) ->
  K.

-spec from_record(jose:public_key() | jose:private_key() | jose:certificate()) -> jwk().
from_record(#'RSAPublicKey'{modulus = N, publicExponent = E}) ->
  #{kty => 'RSA', n => N, e => E};
from_record(#'RSAPrivateKey'{} = K) ->
  Data = #{kty => 'RSA',
           n => K#'RSAPrivateKey'.modulus,
           e => K#'RSAPrivateKey'.publicExponent,
           d => K#'RSAPrivateKey'.privateExponent,
           p => K#'RSAPrivateKey'.prime1,
           q => K#'RSAPrivateKey'.prime2,
           dp => K#'RSAPrivateKey'.exponent1,
           dq => K#'RSAPrivateKey'.exponent2,
           coefficient => K#'RSAPrivateKey'.coefficient},
  maps:filter(fun (_, V) -> V =/= undefined end, Data);
from_record({#'ECPoint'{} = K, {namedCurve, Curve}}) ->
  {X, Y} = jose_crypto:ec_point_to_coordinate(K#'ECPoint'.point),
  #{kty => 'EC',
    crv => pubkey_cert_records:namedCurves(Curve),
    x => X,
    y => Y};
from_record(#'ECPrivateKey'{parameters = {namedCurve, Curve}} = K) ->
  {X, Y} = jose_crypto:ec_point_to_coordinate(K#'ECPrivateKey'.publicKey),
  #{kty => 'EC',
    crv => pubkey_cert_records:namedCurves(Curve),
    d => K#'ECPrivateKey'.privateKey,
    x => X,
    y => Y};
from_record(#'OTPCertificate'{} = C) ->
  SHA1 = jose_pkix:cert_thumbprint(C),
  SHA2 = jose_pkix:cert_thumbprint256(C),
  PubKey = jose_pkix:get_cert_pubkey(C),
  Data = from_record(PubKey),
  Data#{x5t => SHA1, 'x5t#S256' => SHA2}.

-spec from_certificate_chain(jose:certificate_chain()) -> jwk().
from_certificate_chain(Chain) ->
  Certificate = lists:last(Chain),
  Data = from_record(Certificate),
  Data#{x5c => Chain}.

-spec decode(binary() | map()) ->
        {ok, jwk()} | {error, term()}.
decode(Term) ->
  decode(Term, #{}).

-spec decode(binary() | map(), jose_jwk_decoder:options()) ->
        {ok, jwk()} | {error, term()}.
decode(Term, Options) ->
  jose_jwk_decoder:decode(Term, Options).
