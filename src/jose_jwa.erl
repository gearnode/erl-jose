%% Copyright (c) 2020 Bryan Frimin <bryan@frimin.fr>.
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
%% REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
%% AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
%% INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
%% LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
%% OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
%% PERFORMANCE OF THIS SOFTWARE.

-module(jose_jwa).

-export([supported_algorithms/0,
         support/1,
         generate_key/1,
         sign/3,
         verify/4]).

-export_type([alg/0,
              hmac/0,
              ecdsa/0,
              hmac_key/0,
              ecdsa_public_key/0,
              ecdsa_private_key/0,
              sign_key/0,
              verify_key/0]).

-type alg() :: hmac() | ecdsa() | none.
-type hmac() :: hs256 | hs384 | hs512.
-type ecdsa() :: es256 | es384 | es512.

-type hmac_key() :: binary().
-type ecdsa_public_key() :: binary().
-type ecdsa_private_key() :: binary().

-type sign_key() :: hmac_key() | ecdsa_private_key().
-type verify_key() :: hmac_key() | ecdsa_public_key().

-spec supported_algorithms() -> [alg()].
supported_algorithms() ->
    [hs256, hs384, hs512,
     es256, es384, es512,
     none].

-spec support(alg()) -> boolean().
support(Alg) when is_atom(Alg) ->
    lists:member(Alg, supported_algorithms());
support(Alg) ->
    lists:member(Alg, lists:map(fun atom_to_binary/1, supported_algorithms())).

-spec generate_key(alg()) -> hmac_key() | {ecdsa_public_key(), ecdsa_private_key()}.
generate_key(none) ->
    <<>>;
generate_key(hs256) ->
    crypto:strong_rand_bytes(64);
generate_key(hs384) ->
    crypto:strong_rand_bytes(128);
generate_key(hs512) ->
    crypto:strong_rand_bytes(128);
generate_key(es256) ->
    crypto:generate_key(ecdh, secp256r1);
generate_key(es384) ->
    crypto:generate_key(ecdh, secp384r1);
generate_key(es512) ->
    crypto:generate_key(ecdh, secp521r1);
generate_key(_) ->
    error(unsupported_alg).

-spec sign(binary(), alg(), Key) -> binary() when
      Key :: hmac_key() | ecdsa_private_key().
sign(_Value, none, <<>>) ->
    <<>>;
sign(Value, hs256, Key) ->
    crypto:mac(hmac, sha256, Key, Value);
sign(Value, hs384, Key) ->
    crypto:mac(hmac, sha384, Key, Value);
sign(Value, hs512, Key) ->
    crypto:mac(hmac, sha512, Key, Value);
sign(Value, es256, Key) ->
    Signature = crypto:sign(ecdsa, sha256, Value, [Key, secp256r1]),
    decode_ecdsa_sign(Signature, 256);
sign(Value, es384, Key) ->
    Signature = crypto:sign(ecdsa, sha384, Value, [Key, secp384r1]),
    decode_ecdsa_sign(Signature, 384);
sign(Value, es512, Key) ->
    Signature = crypto:sign(ecdsa, sha512, Value, [Key, secp521r1]),
    decode_ecdsa_sign(Signature, 528);
sign(_, _, _) ->
    error(unsupported_alg).

-spec decode_ecdsa_sign(ecdsa_private_key(), non_neg_integer()) -> binary().
decode_ecdsa_sign(Key, Size) ->
    {_, R, S} = public_key:der_decode('ECDSA-Sig-Value', Key),
    <<R:Size, S:Size>>.

-spec verify(binary(), binary(), alg(), Key) -> boolean() when
      Key :: hmac_key() | ecdsa_public_key().
verify(_Value, Signature, none, <<>>) ->
    Signature =:= <<>>;
verify(Value, Signature, hs256, Key) ->
    Signature =:= sign(Value, hs256, Key);
verify(Value, Signature, hs384, Key) ->
    Signature =:= sign(Value, hs384, Key);
verify(Value, Signature, hs512, Key) ->
    Signature =:= sign(Value, hs512, Key);
verify(Value, Signature, es256, Key) ->
    Der = encode_ecdsa_sign(Signature, 256),
    crypto:verify(ecdsa, sha256, Value, Der, [Key, secp256r1]);
verify(Value, Signature, es384, Key) ->
    Der = encode_ecdsa_sign(Signature, 384),
    crypto:verify(ecdsa, sha384, Value, Der, [Key, secp384r1]);
verify(Value, Signature, es512, Key) ->
    Der = encode_ecdsa_sign(Signature, 528),
    crypto:verify(ecdsa, sha512, Value, Der, [Key, secp521r1]);
verify(_, _, _, _) ->
    error(unsupported_alg).

-spec encode_ecdsa_sign(binary(), non_neg_integer()) -> binary().
encode_ecdsa_sign(Value, Size) ->
    <<R:Size/big, S:Size/big>> = Value,
    public_key:der_encode('ECDSA-Sig-Value', {'ECDSA-Sig-Value', R, S}).
