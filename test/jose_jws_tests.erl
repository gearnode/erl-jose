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

-module(jose_jws_tests).

-include_lib("eunit/include/eunit.hrl").

encode_compact_with_none_test_() ->
    JWS = {#{alg => none}, <<"foobar">>},
    [?_assertEqual(<<"eyJhbGciOiJub25lIn0.Zm9vYmFy.">>,
                   jose_jws:encode_compact(JWS, none, <<>>))].

encode_compact_with_hs256_test_() ->
    JWS = {#{alg => hs256}, <<"foobar">>},
    [?_assertEqual(<<"eyJhbGciOiJIUzI1NiJ9.Zm9vYmFy.Rx3jZIUBD3KOZ0CZBK_7ZiTKHK4Nk5FBteHWIYhtVVk">>,
                   jose_jws:encode_compact(JWS, hs256, <<"secret">>))].

encode_compact_with_hs384_test_() ->
    JWS = {#{alg => hs384}, <<"foobar">>},
    [?_assertEqual(<<"eyJhbGciOiJIUzM4NCJ9.Zm9vYmFy.s-8VMgjExqJ5vmNSAHBX2DifHjb-B7w22-JqZlrpdixMA8g8yL26wU4W1_WD678E">>,
                   jose_jws:encode_compact(JWS, hs384, <<"secret">>))].

encode_compact_with_hs512_test_() ->
    JWS = {#{alg => hs512}, <<"foobar">>},
    [?_assertEqual(<<"eyJhbGciOiJIUzUxMiJ9.Zm9vYmFy.devaiaGiy0YT3hn0R9R7J3zEOAJ_HxBLJAjeUeEQvi5wJ2qEDerB5W95ghoAzF3xGcRfM1r7VQ1xsj02fBwk0w">>,
                   jose_jws:encode_compact(JWS, hs512, <<"secret">>))].

% TODO: RSA et ECDSA

encode_compact_with_unsupported_alg_test_() ->
    [?_assertException(error,
                       unsupported_alg,
                       jose_jws:encode_compact({#{alg => hs256}, <<"foobar">>}, foobar, <<"secret">>)),
     ?_assertException(error,
                       unsupported_alg,
                       jose_jws:encode_compact({#{alg => foobar}, <<"foobar">>}, hs256, <<"secret">>))].

%% must({ok, Value}) ->
%%     Value;
%% must(_) ->
%%     erlang:error("must failed").

%% encode_decode({Header, Payload, Key}) ->
%%     Token = jose_jws:encode_compact({Header, Payload}, hs256, Key),
%%     ?assertMatch({ok, {_, _}}, jose_jws:decode_compact(Token, hs256, [<<"lol lol lol">>, Key])).

%% encode_compact_test_() ->
%%     Header0 = #{alg => hs256,
%%                 jku => <<"https://example.com/jku">>,
%%                 kid => <<"b978eb04-8548-4db6-978a-7854757beaf2">>,
%%                 x5u => <<"https://example.com/x5u">>,
%%                 x5t => <<"B5:AC:43:3B:BD:A8:56:49:9D:6B:E2:CF:05:87:F0:9F:96:2D:EC:1C">>,
%%                 'x5t#S256' => <<"76:A3:DD:C6:F4:3A:EA:9B:27:7E:CB:7F:66:01:2F:D3:91:4C:9F:6E:74:9A:2B:D6:04:FD:F2:92:19:9D:04:35">>,
%%                 typ => <<"application/JWS">>,
%%                 cty => <<"application/json; charset=utf-8">>},
%%     Header1 = #{alg => hs256,
%%                 jku => must(uri:parse(<<"https://example.com/jku">>)),
%%                 kid => <<"b978eb04-8548-4db6-978a-7854757beaf2">>,
%%                 x5u => must(uri:parse(<<"https://example.com/x5u">>)),
%%                 x5t => <<"B5:AC:43:3B:BD:A8:56:49:9D:6B:E2:CF:05:87:F0:9F:96:2D:EC:1C">>,
%%                 'x5t#S256' => <<"76:A3:DD:C6:F4:3A:EA:9B:27:7E:CB:7F:66:01:2F:D3:91:4C:9F:6E:74:9A:2B:D6:04:FD:F2:92:19:9D:04:35">>,
%%                 typ => must(jose_media_type:parse(<<"application/JWS">>)),
%%                 cty => must(jose_media_type:parse(<<"application/json; charset=utf-8">>))},
%%     Header2 = #{alg => hs256,
%%                 jku => must(uri:parse(<<"https://example.com/jku">>)),
%%                 kid => <<"b978eb04-8548-4db6-978a-7854757beaf2">>,
%%                 x5u => must(uri:parse(<<"https://example.com/x5u">>)),
%%                 x5t => <<"B5:AC:43:3B:BD:A8:56:49:9D:6B:E2:CF:05:87:F0:9F:96:2D:EC:1C">>,
%%                 'x5t#S256' => <<"76:A3:DD:C6:F4:3A:EA:9B:27:7E:CB:7F:66:01:2F:D3:91:4C:9F:6E:74:9A:2B:D6:04:FD:F2:92:19:9D:04:35">>,
%%                 typ => must(jose_media_type:parse(<<"application/JWS">>)),
%%                 cty => must(jose_media_type:parse(<<"application/json; charset=utf-8">>)),
%%                 crit => [<<"b64">>],
%%                 b64 => false},
%%     Payload = <<"{}">>,
%%     Key = jose_jwa:generate_key(hs256),
%%     [{with, {Header0, Payload, Key}, [fun encode_decode/1]},
%%      {with, {Header1, Payload, Key}, [fun encode_decode/1]},
%%      {with, {Header2, Payload, Key}, [fun encode_decode/1]}].
