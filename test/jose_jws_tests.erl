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

rsa_key_pair() ->
    {ok, F1} = file:read_file("test/fixtures/test-rsa.key"),
    [Entry] = public_key:pem_decode(F1),
    Priv = public_key:pem_entry_decode(Entry),
    {ok, F2} = file:read_file("test/fixtures/test-rsa.pub"),
    [Entry2] = public_key:pem_decode(F2),
    Pub = public_key:pem_entry_decode(Entry2),
    {Pub, Priv}.

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


encode_compact_with_rs256_test_() ->
    {_, Priv} = rsa_key_pair(),
    JWS = {#{alg => rs256}, <<"foobar">>},
    [?_assertEqual(<<"eyJhbGciOiJSUzI1NiJ9.Zm9vYmFy.fd1aA8O89RIsFFnM8rhZDXGkXjx6PPfcg1wtbQ-bheE_D_fci2-_JrGGJJaBAY6yaXVbE2_7a9kjgmCPrY3CGK7-uVuR7rkYMHoR0F1F6HzLLehCukqUs6q2cA8ULIGha2KlQekH78Rgbtpuf5xpfEUbG4SauTVP4HcSSgX-hdbEZfCIcSbmY6HUH2VkAO5IooCUbmuIz1ZOd32U4HvcwW87cLN7KNAy_XNbSx1ON-tPJwk_PJzEXX1f7ncEAv0FG1iw5lUKtSiZapfpJI1ryPN4fvI-nQty9fx9qhwxSqjOVq2IFQtIUVQxHAOF3mHUa7A31ealKAGziSNsYFKjww">>,
                   jose_jws:encode_compact(JWS, rs256, Priv))].

encode_compact_with_rs384_test_() ->
    {_, Priv} = rsa_key_pair(),
    JWS = {#{alg => rs384}, <<"foobar">>},
    [?_assertEqual(<<"eyJhbGciOiJSUzM4NCJ9.Zm9vYmFy.cilcRSvoDRu1QknyqesNRa-HMydA-YCw_bYxOc6LFxYNZzeEDY1lmsmknUds2CALwqpJ1TD8U0N34ZBqAHBEHzSdpyD8lL3Ds-kvR65LWL7v89S2j1XsdnMUU0NpibsPXVKibbmOzqgyyX79Q5TQiFP_jYLY1ethgaMZl-R4Dvp0__nlosT6ckgOGxdI8K3iZvfg4Vkl5lYDc-LLhaJvfzXCq0JYeagilDyR9DkwTb9NDQbmolnuFrtbE_MC4VtNhezkXJ-MtSQjLkJ0WjVY6NDa_sF1318WD2THBeGq2WCfIcmBTOHZ-jYb_peyuDLuRsYS3IigRm1y0H86Gg7-8w">>,
                   jose_jws:encode_compact(JWS, rs384, Priv))].

encode_compact_with_rs512_test_() ->
    {_, Priv} = rsa_key_pair(),
    JWS = {#{alg => rs512}, <<"foobar">>},
    [?_assertEqual(<<"eyJhbGciOiJSUzUxMiJ9.Zm9vYmFy.OE186axg9aZTNGK2vkzOqAHz8UeNx_uaaJj6sk3_82hYrV-5JvAocTeu6aawAfw9aw6PelLxQTHB22BnDHSbUT8fvRM4Hfqm3JKR6Tbcfp2NM2heuE2clcpRGlBqvDkRv4qv8b8X_A52otne1HdIJjPcfOrEKzqNgKRWO2J1Lx7ven_z5szqUMJS7ayKf1b2d0SRC48iVd6c8vebpxkKcazHl00ShTyvKMWQ-ztjBrjyeWQTvjjPPGFxXAX01VsN6nckBMN1KaINhF93re1Sy9q5kwjcqTiVDLBN5vAukV75HSdbHI4sq37qFB0p477J-_55sxU3m_mq9ZCL3xuigg">>,
                   jose_jws:encode_compact(JWS, rs512, Priv))].

%% encode_compact_with_es256_test_() ->
%%     {_, Priv} = rsa_key_pair(),
%%     JWS = {#{alg => es256}, <<"foobar">>},
%%     [?_assertEqual(<<>>,
%%                    jose_jws:encode_compact(JWS, es256, Priv))].

%% encode_compact_with_es384_test_() ->
%%     {_, Priv} = rsa_key_pair(),
%%     JWS = {#{alg => es384}, <<"foobar">>},
%%     [?_assertEqual(<<>>,
%%                    jose_jws:encode_compact(JWS, es384, Priv))].

%% encode_compact_with_es512_test_() ->
%%     {_, Priv} = rsa_key_pair(),
%%     JWS = {#{alg => es512}, <<"foobar">>},
%%     [?_assertEqual(<<>>,
%%                    jose_jws:encode_compact(JWS, es512, Priv))].

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
