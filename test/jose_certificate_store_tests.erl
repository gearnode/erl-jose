%% Copyright (c) 2020-2021 Bryan Frimin <bryan@frimin.fr>.
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

-module(jose_certificate_store_tests).

-include_lib("eunit/include/eunit.hrl").

db_test_() ->
    {spawn,
     {setup,
      fun () -> application:ensure_all_started(jose) end,
      [fun add/0,
       fun remove/0,
       fun find/0]}}.

add() ->
    #{cert := Der, key := _Key} = public_key:pkix_test_root_cert("jose_test", []),
    ?assertEqual(ok, jose_certificate_store:add(certificate_store_default, Der)),
    ?assertEqual(ok, jose_certificate_store:add(certificate_store_default, Der)).

remove() ->
    #{cert := Der, key := _Key} = public_key:pkix_test_root_cert("jose_test", []),
    Sha1 = crypto:hash(sha, Der),
    Sha2 = crypto:hash(sha256, Der),
    ?assertEqual(ok, jose_certificate_store:remove(certificate_store_default, Sha1)),
    ?assertEqual(ok, jose_certificate_store:remove(certificate_store_default, Sha2)),
    ?assertEqual(ok, jose_certificate_store:add(certificate_store_default, Der)),
    ?assertEqual(ok, jose_certificate_store:remove(certificate_store_default, Sha2)),
    ?assertEqual(ok, jose_certificate_store:remove(certificate_store_default, Sha1)).

find() ->
    #{cert := Der, key := _Key} = public_key:pkix_test_root_cert("jose_test", []),
    Cert = public_key:pkix_decode_cert(Der, otp),
    Sha1 = crypto:hash(sha, Der),
    Sha2 = crypto:hash(sha256, Der),
    ?assertEqual(error, jose_certificate_store:find(certificate_store_default, Sha1)),
    ?assertEqual(error, jose_certificate_store:find(certificate_store_default, Sha2)),
    ?assertEqual(ok, jose_certificate_store:add(certificate_store_default, Der)),
    ?assertEqual({ok, Cert}, jose_certificate_store:find(certificate_store_default, {sha1, Sha1})),
    ?assertEqual({ok, Cert}, jose_certificate_store:find(certificate_store_default, {sha2, Sha2})),
    ?assertEqual(ok, jose_certificate_store:remove(certificate_store_default, Der)),
    ?assertEqual(error, jose_certificate_store:find(certificate_store_default, {sha1, Sha1})),
    ?assertEqual(error, jose_certificate_store:find(certificate_store_default, {sha2, Sha2})).
