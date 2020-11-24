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

-module(jose_jws_test).

-include_lib("eunit/include/eunit.hrl").

must({ok, Value}) ->
    Value;
must(_) ->
    erlang:error("must failed").

encode_decode({Header, Payload, Key}) ->
    Token = jose_jws:encode_compact(Header, Payload, hs256, Key),
    ?assertMatch({ok, _, _}, jose_jws:decode_compact(Token, hs256, Key)).

encode_compact_test_() ->
    Header0 = #{alg => hs256,
                jku => <<"https://example.com/jku">>,
                kid => <<"b978eb04-8548-4db6-978a-7854757beaf2">>,
                x5u => <<"https://example.com/x5u">>,
                x5t => <<"B5:AC:43:3B:BD:A8:56:49:9D:6B:E2:CF:05:87:F0:9F:96:2D:EC:1C">>,
                'x5t#S256' => <<"76:A3:DD:C6:F4:3A:EA:9B:27:7E:CB:7F:66:01:2F:D3:91:4C:9F:6E:74:9A:2B:D6:04:FD:F2:92:19:9D:04:35">>,
                typ => <<"application/JWS">>,
                cty => <<"application/json; charset=utf-8">>},
    Header1 = #{alg => hs256,
                jku => must(uri:parse(<<"https://example.com/jku">>)),
                kid => <<"b978eb04-8548-4db6-978a-7854757beaf2">>,
                x5u => must(uri:parse(<<"https://example.com/x5u">>)),
                x5t => <<"B5:AC:43:3B:BD:A8:56:49:9D:6B:E2:CF:05:87:F0:9F:96:2D:EC:1C">>,
                'x5t#S256' => <<"76:A3:DD:C6:F4:3A:EA:9B:27:7E:CB:7F:66:01:2F:D3:91:4C:9F:6E:74:9A:2B:D6:04:FD:F2:92:19:9D:04:35">>,
                typ => must(jose_media_type:parse(<<"application/JWS">>)),
                cty => must(jose_media_type:parse(<<"application/json; charset=utf-8">>))},
    Header2 = #{alg => hs256,
                jku => must(uri:parse(<<"https://example.com/jku">>)),
                kid => <<"b978eb04-8548-4db6-978a-7854757beaf2">>,
                x5u => must(uri:parse(<<"https://example.com/x5u">>)),
                x5t => <<"B5:AC:43:3B:BD:A8:56:49:9D:6B:E2:CF:05:87:F0:9F:96:2D:EC:1C">>,
                'x5t#S256' => <<"76:A3:DD:C6:F4:3A:EA:9B:27:7E:CB:7F:66:01:2F:D3:91:4C:9F:6E:74:9A:2B:D6:04:FD:F2:92:19:9D:04:35">>,
                typ => must(jose_media_type:parse(<<"application/JWS">>)),
                cty => must(jose_media_type:parse(<<"application/json; charset=utf-8">>)),
                crit => [<<"b64">>],
                b64 => false},
    Payload = <<"{}">>,
    Key = jose_jwa:generate_key(hs256),
    [{with, {Header0, Payload, Key}, [fun encode_decode/1]},
     {with, {Header1, Payload, Key}, [fun encode_decode/1]},
     {with, {Header2, Payload, Key}, [fun encode_decode/1]}].
