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

-module(jose_jwa_tests).

-include_lib("eunit/include/eunit.hrl").

unsupported_alg_test_() ->
  [?_assertException(error, unsupported_alg,
                     jose_jwa:generate_key(foobar)),
   ?_assertException(error, unsupported_alg,
                     jose_jwa:sign(<<"foo">>, foobar, <<"$cret">>)),
   ?_assertException(error, unsupported_alg,
                     jose_jwa:is_valid(<<"foo">>, <<>>, foobar, <<"$cret">>))].

jwa_test_() ->
  [fun encode_alg/0,
   fun decode_alg/0,
   fun sign_and_verify_none/0,
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
  ?assert(jose_jwa:support(none)),
  Key = jose_jwa:generate_key(none),
  Msg = <<"hello world">>,
  Signature = jose_jwa:sign(Msg, none, Key),
  ?assertEqual(<<>>, Signature),
  ?assert(jose_jwa:is_valid(Msg, Signature, none, Key)),
  Msg2 = <<"other message">>,
  Signature2 = jose_jwa:sign(Msg2, none, Key),
  ?assertEqual(<<>>, Signature2),
  ?assertEqual(Signature, Signature2).

sign_and_verify_hmac(Alg) ->
  ?assert(jose_jwa:support(Alg)),
  Key = jose_jwa:generate_key(Alg),
  Msg = <<"hello world">>,
  Signature = jose_jwa:sign(Msg, Alg, Key),
  ?assertNotEqual(<<>>, Signature),
  ?assert(jose_jwa:is_valid(Msg, Signature, Alg, Key)),
  Key2 = jose_jwa:generate_key(Alg),
  ?assertNot(jose_jwa:is_valid(Msg, Signature, Alg, Key2)),
  Msg2 = <<"other message">>,
  ?assertNot(jose_jwa:is_valid(Msg2, Signature, Alg, Key)).

sign_and_verify_asymmetric(Alg) ->
  ?assert(jose_jwa:support(none)),
  {Pub, Priv} = jose_jwa:generate_key(Alg),
  Msg = <<"hello world">>,
  Signature = jose_jwa:sign(Msg, Alg, Priv),
  ?assertNotEqual(<<>>, Signature),
  ?assert(jose_jwa:is_valid(Msg, Signature, Alg, Pub)),
  {Pub2, Priv2} = jose_jwa:generate_key(Alg),
  ?assertNot(jose_jwa:is_valid(Msg, Signature, Alg, Pub2)),
  Msg2 = <<"other message">>,
  Signature2 = jose_jwa:sign(Msg2, Alg, Priv2),
  ?assertNotEqual(<<>>, Signature2),
  ?assert(jose_jwa:is_valid(Msg2, Signature2, Alg, Pub2)).

encode_alg() ->
  ?assertException(error, unsupported_alg,
                   jose_jwa:encode_alg(<<"foo">>)),
  ?assertMatch(<<"none">>,
               jose_jwa:encode_alg(none)),
  ?assertMatch(<<"HS256">>,
               jose_jwa:encode_alg(hs256)),
  ?assertMatch(<<"HS384">>,
               jose_jwa:encode_alg(hs384)),
  ?assertMatch(<<"HS512">>,
               jose_jwa:encode_alg(hs512)),
  ?assertMatch(<<"ES256">>,
               jose_jwa:encode_alg(es256)),
  ?assertMatch(<<"ES384">>,
               jose_jwa:encode_alg(es384)),
  ?assertMatch(<<"ES512">>,
               jose_jwa:encode_alg(es512)),
  ?assertMatch(<<"RS256">>,
               jose_jwa:encode_alg(rs256)),
  ?assertMatch(<<"RS384">>,
               jose_jwa:encode_alg(rs384)),
  ?assertMatch(<<"RS512">>,
               jose_jwa:encode_alg(rs512)).

decode_alg() ->
  ?assertMatch({error, unsupported_alg},
               jose_jwa:decode_alg(<<"foo">>)),
  ?assertMatch({ok, none},
               jose_jwa:decode_alg(<<"none">>)),
  ?assertMatch({ok, hs256},
               jose_jwa:decode_alg(<<"HS256">>)),
  ?assertMatch({ok, hs384},
               jose_jwa:decode_alg(<<"HS384">>)),
  ?assertMatch({ok, hs512},
               jose_jwa:decode_alg(<<"HS512">>)),
  ?assertMatch({ok, es256},
               jose_jwa:decode_alg(<<"ES256">>)),
  ?assertMatch({ok, es384},
               jose_jwa:decode_alg(<<"ES384">>)),
  ?assertMatch({ok, es512},
               jose_jwa:decode_alg(<<"ES512">>)),
  ?assertMatch({ok, rs256},
               jose_jwa:decode_alg(<<"RS256">>)),
  ?assertMatch({ok, rs384},
               jose_jwa:decode_alg(<<"RS384">>)),
  ?assertMatch({ok, rs512},
               jose_jwa:decode_alg(<<"RS512">>)).
