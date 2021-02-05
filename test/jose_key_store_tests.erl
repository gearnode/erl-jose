%% Copyright (c) 2020, 2021 Bryan Frimin <bryan@frimin.fr>.
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

-module(jose_key_store_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

db_test_() ->
    {spawn,
     {setup,
      fun () -> application:ensure_all_started(jose) end,
      [fun add/0,
       fun remove/0,
       fun find/0]}}.

genkey() ->
    PrivKey = public_key:generate_key({rsa, 4096, 65537}),
    PubKey = #'RSAPublicKey'{modulus=PrivKey#'RSAPrivateKey'.modulus, publicExponent=PrivKey#'RSAPrivateKey'.publicExponent},
    {PubKey, PrivKey}.

add() ->
    {PubKey, PrivKey} = genkey(),
    PemEntry = public_key:pem_entry_encode('SubjectPublicKeyInfo', PubKey),
    ?assertEqual(ok, jose_key_store:add(key_store_default, PemEntry)),
    ?assertEqual(ok, jose_key_store:add(key_store_default, PemEntry)),
    ?assertEqual(error, jose_key_store:add(key_store_default, PubKey)),
    ?assertEqual(error, jose_key_store:add(key_store_default, PrivKey)).

remove() ->
    {PubKey, _PrivKey} = genkey(),
    PemEntry = public_key:pem_entry_encode('SubjectPublicKeyInfo', PubKey),
    {_, Der, _} = PemEntry,
    KId = crypto:hash(md5, Der),
    ?assertEqual(ok, jose_key_store:remove(key_store_default, KId)),
    ?assertEqual(ok, jose_key_store:add(key_store_default, PemEntry)),
    ?assertEqual(ok, jose_key_store:remove(key_store_default, KId)).

find() ->
    {PubKey, _PrivKey} = genkey(),
    PemEntry = public_key:pem_entry_encode('SubjectPublicKeyInfo', PubKey),
    {_, Der, _} = PemEntry,
    KId = crypto:hash(md5, Der),
    ?assertEqual(error, jose_key_store:find(key_store_default, KId)),
    ?assertEqual(ok, jose_key_store:add(key_store_default, PemEntry)),
    ?assertEqual({ok, PubKey}, jose_key_store:find(key_store_default, KId)),
    ?assertEqual(ok, jose_key_store:remove(key_store_default, KId)),
    ?assertEqual(error, jose_key_store:find(key_store_default, KId)).
