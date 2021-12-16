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

-module(jose_jwa).

-include_lib("public_key/include/public_key.hrl").

-export([reserved_header_parameter_names/0,
         supported_algorithms/0,
         support/1,
         encode_alg/1,
         decode_alg/1,
         generate_key/1,
         sign/3,
         is_valid/4]).

-export_type([alg/0,
              hmac/0,
              ecdsa/0,
              rsa/0,
              hmac_key/0,
              sign_key/0,
              verify_key/0,
              decode_alg_error_reason/0]).

-type alg() :: hmac() | ecdsa() | rsa() | none.
-type hmac() :: hs256 | hs384 | hs512.
-type ecdsa() :: es256 | es384 | es521.
-type rsa() :: rs256 | rs384 | rs512.

-type hmac_key() :: binary().

-type sign_key() :: hmac_key() | public_key:public_key().
-type verify_key() :: hmac_key() | public_key:private_key().

-type decode_alg_error_reason() :: unsupported_alg.

-spec reserved_header_parameter_names() ->
        [jose:header_parameter_name()].
reserved_header_parameter_names() ->
  [<<"epk">>, <<"apu">>, <<"apv">>, <<"iv">>, <<"tag">>,
   <<"p2c">>, <<"p2c">>, <<"enc">>, <<"kty">>, <<"crv">>,
   <<"x">>, <<"y">>, <<"d">>, <<"e">>, <<"d">>, <<"p">>,
   <<"q">>, <<"dp">>, <<"dq">>, <<"qi">>, <<"oth">>, <<"k">>].

-spec supported_algorithms() ->
        [alg()].
supported_algorithms() ->
  [hs256, hs384, hs512,
   es256, es384, es521,
   rs256, rs384, rs512,
   none].

-spec support(alg()) ->
        boolean().
support(Alg) ->
    lists:member(Alg, supported_algorithms()).

-spec encode_alg(alg()) ->
        binary().
encode_alg(none) ->
  <<"none">>;
encode_alg(hs256) ->
  <<"HS256">>;
encode_alg(hs384) ->
  <<"HS384">>;
encode_alg(hs512) ->
  <<"HS512">>;
encode_alg(es256) ->
  <<"ES256">>;
encode_alg(es384) ->
  <<"ES384">>;
encode_alg(es521) ->
  <<"ES521">>;
encode_alg(rs256) ->
  <<"RS256">>;
encode_alg(rs384) ->
  <<"RS384">>;
encode_alg(rs512) ->
  <<"RS512">>;
encode_alg(_Alg) ->
  error(unsupported_alg).

-spec decode_alg(binary()) ->
        {ok, alg()} | {error, unsupported_alg}.
decode_alg(<<"none">>) ->
  {ok, none};
decode_alg(<<"HS256">>) ->
  {ok, hs256};
decode_alg(<<"HS384">>) ->
  {ok, hs384};
decode_alg(<<"HS512">>) ->
  {ok, hs512};
decode_alg(<<"ES256">>) ->
  {ok, es256};
decode_alg(<<"ES384">>) ->
  {ok, es384};
decode_alg(<<"ES521">>) ->
  {ok, es521};
decode_alg(<<"RS256">>) ->
  {ok, rs256};
decode_alg(<<"RS384">>) ->
  {ok, rs384};
decode_alg(<<"RS512">>) ->
  {ok, rs512};
decode_alg(_Alg) ->
  {error, unsupported_alg}.

-spec generate_key(alg()) ->
        hmac_key() | {public_key:public_key(), public_key:private_key()}.
generate_key(none) ->
  <<>>;
generate_key(hs256) ->
  crypto:strong_rand_bytes(64);
generate_key(hs384) ->
  crypto:strong_rand_bytes(128);
generate_key(hs512) ->
  crypto:strong_rand_bytes(128);
generate_key(es256) ->
  PrivKey = public_key:generate_key({namedCurve, secp256r1}),
  PubKey = {#'ECPoint'{point=PrivKey#'ECPrivateKey'.publicKey}, {namedCurve, secp256r1}},
  {PubKey, PrivKey};
generate_key(es384) ->
  PrivKey = public_key:generate_key({namedCurve, secp384r1}),
  PubKey = {#'ECPoint'{point=PrivKey#'ECPrivateKey'.publicKey}, {namedCurve, secp384r1}},
  {PubKey, PrivKey};
generate_key(es521) ->
  PrivKey = public_key:generate_key({namedCurve, secp521r1}),
  PubKey = {#'ECPoint'{point=PrivKey#'ECPrivateKey'.publicKey}, {namedCurve, secp521r1}},
  {PubKey, PrivKey};
generate_key(rs256) ->
  PrivKey = public_key:generate_key({rsa, 4096, 65537}),
  PubKey = #'RSAPublicKey'{modulus=PrivKey#'RSAPrivateKey'.modulus,
                           publicExponent=PrivKey#'RSAPrivateKey'.publicExponent},
  {PubKey, PrivKey};
generate_key(rs384) ->
  PrivKey = public_key:generate_key({rsa, 4096, 65537}),
  PubKey = #'RSAPublicKey'{modulus=PrivKey#'RSAPrivateKey'.modulus,
                           publicExponent=PrivKey#'RSAPrivateKey'.publicExponent},
  {PubKey, PrivKey};
generate_key(rs512) ->
  PrivKey = public_key:generate_key({rsa, 4096, 65537}),
  PubKey = #'RSAPublicKey'{modulus=PrivKey#'RSAPrivateKey'.modulus,
                           publicExponent=PrivKey#'RSAPrivateKey'.publicExponent},
  {PubKey, PrivKey};
generate_key(_) ->
  error(unsupported_alg).

-spec sign(binary(), alg(), Key) ->
        binary()
          when Key :: hmac_key() | public_key:private_key().
sign(_Value, none, <<>>) ->
  <<>>;
sign(Value, hs256, Key) ->
  crypto:mac(hmac, sha256, Key, Value);
sign(Value, hs384, Key) ->
  crypto:mac(hmac, sha384, Key, Value);
sign(Value, hs512, Key) ->
  crypto:mac(hmac, sha512, Key, Value);
sign(Value, es256, Key) ->
  public_key:sign(Value, sha256, Key);
sign(Value, es384, Key) ->
  public_key:sign(Value, sha384, Key);
sign(Value, es521, Key) ->
  public_key:sign(Value, sha512, Key);
sign(Value, rs256, Key) ->
  public_key:sign(Value, sha256, Key);
sign(Value, rs384, Key) ->
  public_key:sign(Value, sha384, Key);
sign(Value, rs512, Key) ->
  public_key:sign(Value, sha512, Key);
sign(_, _, _) ->
  error(unsupported_alg).

-spec is_valid(binary(), binary(), alg(), Key) ->
        boolean()
          when Key :: hmac_key() | public_key:public_key().
is_valid(_Value, Signature, none, <<>>) ->
  Signature =:= <<>>;
is_valid(_Value, _Signature, none, _) ->
  false;
is_valid(Value, Signature, hs256, Key) ->
  Signature =:= sign(Value, hs256, Key);
is_valid(Value, Signature, hs384, Key) ->
  Signature =:= sign(Value, hs384, Key);
is_valid(Value, Signature, hs512, Key) ->
  Signature =:= sign(Value, hs512, Key);
is_valid(Value, Signature, es256, Key) ->
  public_key:verify(Value, sha256, Signature, Key);
is_valid(Value, Signature, es384, Key) ->
  public_key:verify(Value, sha384, Signature, Key);
is_valid(Value, Signature, es521, Key) ->
  public_key:verify(Value, sha512, Signature, Key);
is_valid(Value, Signature, rs256, Key) ->
  public_key:verify(Value, sha256, Signature, Key);
is_valid(Value, Signature, rs384, Key) ->
  public_key:verify(Value, sha384, Signature, Key);
is_valid(Value, Signature, rs512, Key) ->
  public_key:verify(Value, sha512, Signature, Key);
is_valid(_, _, _, _) ->
  error(unsupported_alg).
