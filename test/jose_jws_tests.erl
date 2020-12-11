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

generate_media_types() ->
    MediaTypes = [<<"text/plain">>, <<"application/json">>, <<"application/jwk+json">>,
                  <<"application/jwk-set+json">>, <<"application/jwt">>, <<"text/xml">>],
    [MT || {ok, MT} <- lists:map(fun jose_media_type:parse/1, MediaTypes)].

generate_uri() ->
    URIs = [<<"https://example.com">>, <<"http://example.com?bar">>, <<"https://www.frimin.fr/dns.html">>],
    [URI || {ok, URI} <- lists:map(fun uri:parse/1, URIs)].

generate_headers(Alg) ->
    #{cert := Der, key := _Key} = public_key:pkix_test_root_cert("jose_test", []),
    X5C = [public_key:pkix_decode_cert(Der, otp)],
    X5T = crypto:hash(sha, Der),
    X5T2 = crypto:hash(sha256, Der),

    [#{alg => Alg, kid => KId, jku => JKU,
       x5u => X5U, cty => Cty, typ => Typ,
       b64 => B64, crit => [<<"b64">>],
       x5c => X5C, x5t => X5T, 'x5t#S256' => X5T2, <<"foo">> => <<"bar">>} ||
        KId <- [<<>>, <<"john.doe@example.com">>, <<"0ujsszwN8NRY24YaXiTIE2VWDTS">>],
        Cty <- generate_media_types(),
        Typ <- generate_media_types(),
        JKU <- generate_uri(),
        X5U <- generate_uri(),
        B64 <- [true, false]].

encode_decode_encode(Header, Payload) ->
    fun() ->
            Token = jose_jws:encode_compact({Header, Payload}, none, <<>>),
            ?assertEqual({ok, {Header, Payload}}, jose_jws:decode_compact(Token, none, <<>>)),
            ?assertEqual(Token, jose_jws:encode_compact({Header, Payload}, none, <<>>))
    end.

decode_encode_properties_test_() ->
    [encode_decode_encode(Header, <<"hello world">>) || Header <- generate_headers(none)].

encode_compact_test_() ->
    [fun encode_compact_with_invalid_alg/0].

encode_compact_with_invalid_alg() ->
    ?assertException(error, unsupported_alg,
                     jose_jws:encode_compact({#{alg => foobar}, <<"{}">>}, none, <<>>)).

decode_compact_test_() ->
    [fun decode_jws_with_invalid_format/0,
     fun decode_jws_with_invalid_header_base64_encoding/0,
     fun decode_jws_with_invalid_alg_header/0,
     fun decode_jws_with_invalid_kid_header/0,
     fun decode_jws_with_invalid_jku_header/0,
     fun decode_jws_with_invalid_x5u_header/0,
     fun decode_jws_with_invalid_x5c_header/0,
     fun decode_jws_with_invalid_x5t_header/0,
     fun decode_jws_with_invalid_x5ts256_header/0,
     fun decode_jws_with_invalid_typ_header/0,
     fun decode_jws_with_invalid_cty_header/0,
     fun decode_jws_with_invalid_crit_header/0,
     fun decode_jws_with_invalid_b64_header/0,
     fun decode_jws_with_header_duplicated_json_key/0,
     fun decode_jws_with_bad_map_header/0,
     fun decode_jws_with_invalid_ut8_encoding_header/0,
     fun decode_jws_with_invalid_payload/0,
     fun decode_jws_with_invalid_signature/0,
     fun decode_jws_with_invalid_non_base64_payload/0,
     fun decode_jws_with_mismatch_alg/0].

decode_jws_with_invalid_format() ->
    ?assertEqual({error, invalid_format},
                 jose_jws:decode_compact(<<"foobar">>, hs256, <<"secret">>)),
    ?assertEqual({error, invalid_format},
                 jose_jws:decode_compact(<<"foo.bar">>, hs256, <<"secret">>)),
    ?assertEqual({error, invalid_format},
                 jose_jws:decode_compact(<<"foo.bar.baz.fiz">>, hs256, <<"secret">>)).

decode_jws_with_invalid_header_base64_encoding() ->
    ?assertMatch({error, {invalid_header, _}},
                 jose_jws:decode_compact(<<"fo^^o.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, _}},
                 jose_jws:decode_compact(<<"foobar.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, invalid_encoding}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1dSI6Imh0dHBzOi8vZXhhbXBsZS5jb20ifQ==.e30.">>, none, <<>>)).

decode_jws_with_invalid_alg_header() ->
    ?assertEqual({error, {invalid_header, alg, unsupported_alg}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJpbnZhbGlkIn0.e30.">>, none, <<>>)),
    ?assertEqual({error, {invalid_header, alg, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOjEyM30.e30.">>, none, <<>>)).

decode_jws_with_invalid_kid_header() ->
    ?assertEqual({error, {invalid_header, kid, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsImtpZCI6MTIzfQ.e30.">>, none, <<>>)).

decode_jws_with_invalid_jku_header() ->
    ?assertEqual({error, {invalid_header, jku, {truncated_percent_sequence, <<"%">>}}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsImprdSI6IiUifQ.e30.">>, none, <<>>)),
    ?assertEqual({error, {invalid_header, jku, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsImprdSI6MTIzfQ.e39.">>, none, <<>>)).

decode_jws_with_invalid_x5u_header() ->
    ?assertEqual({error, {invalid_header, x5u, {truncated_percent_sequence, <<"%">>}}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1dSI6IiUifQ.e30.">>, none, <<>>)),
    ?assertEqual({error, {invalid_header, x5u, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1dSI6MTIzfQ.e30.">>, none, <<>>)).

decode_jws_with_invalid_x5c_header() ->
    ?assertEqual({error, {invalid_header, x5c, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1YyI6W119.e30.">>, none, <<>>)),
    ?assertEqual({error, {invalid_header, x5c, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1YyI6ImEifQ.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, x5c, {invalid_data, _}}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1YyI6WyJhIl19.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, x5c, {invalid_data, _}}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1YyI6WyJaZyJdfQ.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, x5c, _}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1YyI6WyJaZz09Il19.e30.">>, none, <<>>)).
    % TODO: add test with one validate element and one bad element.

decode_jws_with_invalid_x5t_header() ->
    ?assertMatch({error, {invalid_header, x5t, {invalid_data, _}}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1dCI6IlpnIn0.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, x5t, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1dCI6MTIzfQ.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, x5t, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1dCI6IlpnPT0ifQ.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, x5t, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1dCI6IllXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRmgifQ.e30.">>, none, <<>>)).

decode_jws_with_invalid_x5ts256_header() ->
    ?assertMatch({error, {invalid_header, 'x5t#S256', {invalid_data, _}}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1dCNTMjU2IjoiWmcifQ.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, 'x5t#S256', invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1dCNTMjU2IjoxMjN9.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, 'x5t#S256', invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1dCNTMjU2IjoiWmc9PSJ9.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, 'x5t#S256', invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsIng1dCNTMjU2IjoiWVdGaFlXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdGaFlXRmhZV0ZoWVdFPSJ9.e30.">>, none, <<>>)).

decode_jws_with_invalid_typ_header() ->
    ?assertMatch({error, {invalid_header, typ, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsInR5cCI6ImZvbyJ9.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, typ, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsInR5cCI6MTIzfQ.e30.">>, none, <<>>)).

decode_jws_with_invalid_cty_header() ->
    ?assertMatch({error, {invalid_header, cty, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsImN0eSI6ImZvbyJ9.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, cty, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsImN0eSI6MTIzfQ.e30.">>, none, <<>>)).

decode_jws_with_invalid_crit_header() ->
    ?assertMatch({error, {invalid_header, crit, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsImNyaXQiOltdfQ.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, crit, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsImNyaXQiOjEyM30.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, crit, illegal_parameter_name}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsImNyaXQiOlsia2lkIl19.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, crit, illegal_parameter_name}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiYjY0Iiwia2lkIl19.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, crit, unsupported}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiZm9vIl19.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, crit, unsupported}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiYjY0IiwiZm9vIl19.e30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_header, crit, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiYjY0IiwxMjNdfQ.e30.">>, none, <<>>)).

decode_jws_with_invalid_b64_header() ->
    ?assertMatch({error, {invalid_header, b64, invalid_format}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsImI2NCI6ImZvbyJ9.e30.">>, none, <<>>)).

decode_jws_with_header_duplicated_json_key() ->
    ?assertEqual({error, {invalid_header, #{position => {1,16}, reason => {duplicate_key, <<"alg">>}}}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiIsImFsZyI6Im5vbmUifQ.e30.">>, none, <<>>)).

decode_jws_with_bad_map_header() ->
    ?assertEqual({error, {invalid_header, invalid_format}},
                 jose_jws:decode_compact(<<"ImhlbGxvIg.e30.">>, none, <<>>)).

decode_jws_with_invalid_ut8_encoding_header() ->
    ?assertEqual({error, {invalid_header, #{position => {1,9}, reason => invalid_escape_sequence}}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJceEUwXHg4MFx4ODAifQ.e30.">>, none, <<>>)).

decode_jws_with_invalid_payload() ->
    ?assertMatch({error, {invalid_payload, {invalid_base64_char, _}}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiJ9.fo^^o.">>, none, <<>>)).

decode_jws_with_invalid_signature() ->
    ?assertMatch({error, {invalid_signature, {invalid_base64_char, _}}},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiJ9.e30.f^^o">>, none, <<>>)).

decode_jws_with_invalid_non_base64_payload() ->
    ?assertMatch({error, invalid_format},
                 jose_jws:decode_compact(<<"eyJiNjQiOmZhbHNlLCJhbGciOiJub25lIn0.a.b.">>, none, <<>>)).

decode_jws_with_mismatch_alg() ->
    ?assertMatch({error, alg_mismatch},
                 jose_jws:decode_compact(<<"eyJhbGciOiJIUzI1NiJ9.e30.">>, none, <<>>)).
