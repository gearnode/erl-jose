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

-module(jose_jwa_tests).

-include_lib("eunit/include/eunit.hrl").

jwa_test_() ->
     [fun sign_and_verify_none/0,
      {with, hs256, [fun sign_and_verify_hmac/1]},
      {with, hs384, [fun sign_and_verify_hmac/1]},
      {with, hs512, [fun sign_and_verify_hmac/1]},
      {with, es256, [fun sign_and_verify_asymmetric/1]},
      {with, es384, [fun sign_and_verify_asymmetric/1]},
      {with, es512, [fun sign_and_verify_asymmetric/1]},
      {with, rs256, [fun sign_and_verify_asymmetric/1]},
      {with, rs384, [fun sign_and_verify_asymmetric/1]},
      {with, rs512, [fun sign_and_verify_asymmetric/1]}].

sign_and_verify_none() ->
    Key = jose_jwa:generate_key(none),
    Msg = <<"hello world">>,
    Signature = jose_jwa:sign(Msg, none, Key),
    ?assertEqual(<<>>, Signature),
    ?assert(jose_jwa:verify(Msg, Signature, none, Key)),
    Msg2 = <<"other message">>,
    Signature2 = jose_jwa:sign(Msg2, none, Key),
    ?assertEqual(<<>>, Signature2),
    ?assertEqual(Signature, Signature2).

sign_and_verify_hmac(Alg) ->
    Key = jose_jwa:generate_key(Alg),
    Msg = <<"hello world">>,
    Signature = jose_jwa:sign(Msg, Alg, Key),
    ?assertNotEqual(<<>>, Signature),
    ?assert(jose_jwa:verify(Msg, Signature, Alg, Key)),
    Key2 = jose_jwa:generate_key(Alg),
    ?assertNot(jose_jwa:verify(Msg, Signature, Alg, Key2)),
    Msg2 = <<"other message">>,
    ?assertNot(jose_jwa:verify(Msg2, Signature, Alg, Key)).

sign_and_verify_asymmetric(Alg) ->
    {Pub, Priv} = jose_jwa:generate_key(Alg),
    Msg = <<"hello world">>,
    Signature = jose_jwa:sign(Msg, Alg, Priv),
    ?assertNotEqual(<<>>, Signature),
    ?assert(jose_jwa:verify(Msg, Signature, Alg, Pub)),
    {Pub2, Priv2} = jose_jwa:generate_key(Alg),
    ?assertNot(jose_jwa:verify(Msg, Signature, Alg, Pub2)),
    Msg2 = <<"other message">>,
    Signature2 = jose_jwa:sign(Msg2, Alg, Priv2),
    ?assertNotEqual(<<>>, Signature2),
    ?assert(jose_jwa:verify(Msg2, Signature2, Alg, Pub2)).
