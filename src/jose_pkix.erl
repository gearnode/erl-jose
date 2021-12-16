%% Copyright (c) 2020, 2021 Exograd SAS.
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

-module(jose_pkix).

-include_lib("public_key/include/public_key.hrl").

-export([get_cert_pubkey/1, get_cert_chain_pubkey/1,
         privkey_to_pubkey/1,
         cert_thumbprint/1, cert_thumbprint256/1]).

-spec get_cert_pubkey(jose:certificate()) -> jose:public_key().
get_cert_pubkey(Certificate) ->
  PubKey =
    Certificate#'OTPCertificate'.tbsCertificate
    #'OTPTBSCertificate'.subjectPublicKeyInfo
    #'OTPSubjectPublicKeyInfo'.subjectPublicKey,
  case PubKey of
    #'ECPoint'{} ->
      Curve =
        pubkey_cert_records:namedCurves(jose_crypto:get_ec_curve(PubKey)),
      {PubKey, {namedCurve, Curve}};
    _ ->
      PubKey
  end.

-spec get_cert_chain_pubkey(jose:certificate_chain()) ->
        {ok, jose:public_key()} | {error, term()}.
get_cert_chain_pubkey([]) ->
  {error, invalid_certificate_chain};
get_cert_chain_pubkey([Root | _] = Chain) ->
  case public_key:pkix_path_validation(Root, Chain, []) of
    {ok, {PublicKeyInfo, _}} ->
      {ok, PublicKeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey};
    {error, Reason} ->
      {error, {invalid_certificate_chain, Reason}}
  end.

-spec privkey_to_pubkey(jose:public_key() | jose:private_key()) ->
        jose:public_key().
privkey_to_pubkey(#'RSAPublicKey'{} = PubKey) ->
  PubKey;
privkey_to_pubkey(#'RSAPrivateKey'{modulus = N, publicExponent = E}) ->
  #'RSAPublicKey'{modulus = N, publicExponent = E};
privkey_to_pubkey({#'ECPoint'{}, _} = PubKey) ->
  PubKey;
privkey_to_pubkey(#'ECPrivateKey'{parameters = {namedCurve, Curve},
                                  publicKey = PubKey}) ->
  {#'ECPoint'{point = PubKey}, Curve}.
  
-spec cert_thumbprint(jose:certificate()) -> jose:certificate_thumbprint().
cert_thumbprint(Certificate) ->
  Der = public_key:pkix_encode('OTPCertificate', Certificate, otp),
  crypto:hash(sha, Der).

-spec cert_thumbprint256(jose:certificate()) -> jose:certificate_thumbprint().
cert_thumbprint256(Certificate) ->
  Der = public_key:pkix_encode('OTPCertificate', Certificate, otp),
  crypto:hash(sha256, Der).
