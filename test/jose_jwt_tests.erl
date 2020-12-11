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

-module(jose_jwt_tests).

-include_lib("eunit/include/eunit.hrl").

decode_compact_with_jws_envelop_test_() ->
    [fun decode_compact_in_jws_envelop_with_invalid_format/0,
     fun decode_compact_in_jws_envelop_with_invalid_iss_claim/0,
     fun decode_compact_in_jws_envelop_with_invalid_sub_claim/0,
     fun decode_compact_in_jws_envelop_with_invalid_aud_claim/0,
     fun decode_compact_in_jws_envelop_with_mismatch_aud_claim/0,
     fun decode_compact_in_jws_envelop_with_invalid_exp_claim/0,
     fun decode_compact_in_jws_envelop_with_expire_exp_claim/0,
     fun decode_compact_in_jws_envelop_with_invalid_nbf_claim/0,
     fun decode_compact_in_jws_envelop_with_not_started_nbf_claim/0,
     fun decode_compact_in_jws_envelop_with_invalid_iat_claim/0,
     fun decode_compact_in_jws_envelop_with_invalid_jti/0,
     fun decode_compact_in_jws_envelop_with_invalid_payload/0,
     fun decode_compact_in_jws_envelop_with_payload_duplicated_json_key/0,
     fun decode_compact_in_jws_envelop_with_bad_map_payload/0,
     fun decode_compact_in_jws_envelop_with_invalid_utf8_encoding_payload/0,
     fun decode_compact_in_jws_enevlop_with_mismatch_header_replicated_claims/0].

decode_compact_in_jws_envelop_with_invalid_format() ->
    ?assertEqual({error, invalid_format},
                 jose_jwt:decode_compact(<<"a.b">>, none, <<>>)).

decode_compact_in_jws_envelop_with_invalid_iss_claim() ->
    ?assertMatch({error, {invalid_claim, iss, invalid_format}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJpc3MiOjEyM30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_claim, iss, _}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJpc3MiOiJmb286JTYifQ.">>, none, <<>>)).

decode_compact_in_jws_envelop_with_invalid_sub_claim() ->
    ?assertMatch({error, {invalid_claim, sub, invalid_format}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJzdWIiOjEyM30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_claim, sub, _}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJzdWIiOiJmb286JTYifQ.">>, none, <<>>)).

decode_compact_in_jws_envelop_with_invalid_aud_claim() ->
    ?assertMatch({error, {invalid_claim, aud, invalid_format}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJhdWQiOjEyM30.">>, none, <<>>)),
    ?assertMatch({error, {invalid_claim, aud, invalid_format}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJhdWQiOlsiYSIsMTIzXX0.">>, none, <<>>)),
    ?assertMatch({error, {invalid_claim, aud, {truncated_percent_sequence, _}}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJhdWQiOiJmb286JTYifQ.">>, none, <<>>)),
    ?assertMatch({error, {invalid_claim, aud, {truncated_percent_sequence, _}}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJhdWQiOlsib2siLCJmb286JTYiXX0.">>, none, <<>>)).

decode_compact_in_jws_envelop_with_mismatch_aud_claim() ->
    ?assertMatch({error, {invalid_claim, aud, mismatch}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJhdWQiOlsiZm9vIiwiYmFyIl19.">>, none, <<>>)),
    ?assertMatch({error, {invalid_claim, aud, mismatch}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJhdWQiOiJmb28ifQ.">>, none, <<>>)).

decode_compact_in_jws_envelop_with_invalid_exp_claim() ->
    ?assertMatch({error, {invalid_claim, exp, invalid_format}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJleHAiOiJmb28ifQ.">>, none, <<>>)),
    ?assertMatch({error, {invalid_claim, exp, invalid_format}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJleHAiOjEuMH0.">>, none, <<>>)).

decode_compact_in_jws_envelop_with_expire_exp_claim() ->
    ?assertMatch({error, {invalid_claim, exp, not_valid_anymore}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJleHAiOjB9.">>, none, <<>>)).

decode_compact_in_jws_envelop_with_invalid_nbf_claim() ->
    ?assertMatch({error, {invalid_claim, nbf, invalid_format}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJuYmYiOiJmb28ifQ.">>, none, <<>>)),
    ?assertMatch({error, {invalid_claim, nbf, invalid_format}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJuYmYiOjEuMH0.">>, none, <<>>)).

decode_compact_in_jws_envelop_with_not_started_nbf_claim() ->
    ?assertMatch({error, {invalid_claim, nbf, not_valid_yet}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJuYmYiOjMyNTMzNDYzOTU5fQ.">>, none, <<>>)).

decode_compact_in_jws_envelop_with_invalid_iat_claim() ->
    ?assertMatch({error, {invalid_claim, iat, invalid_format}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJpYXQiOiJmb28ifQ.">>, none, <<>>)),
    ?assertMatch({error, {invalid_claim, iat, invalid_format}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJpYXQiOjEuMH0.">>, none, <<>>)).

decode_compact_in_jws_envelop_with_invalid_jti() ->
    ?assertMatch({error, {invalid_claim, jti, invalid_format}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJqdGkiOjEyM30.">>, none, <<>>)).

decode_compact_in_jws_envelop_with_invalid_payload() ->
    ?assertMatch({error, {invalid_payload, {invalid_base64_char, _}}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.f^^o.">>, none, <<>>)).

decode_compact_in_jws_envelop_with_payload_duplicated_json_key() ->
    ?assertEqual({error, {invalid_payload, #{position => {1,14}, reason => {duplicate_key, <<"foo">>}}}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJmb28iOiJiYXIiLCJmb28iOiJub25lIn0.">>, none, <<>>)).

decode_compact_in_jws_envelop_with_bad_map_payload() ->
    ?assertEqual({error, {invalid_payload, invalid_format}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.ImZvbyI.">>, none, <<>>)).

decode_compact_in_jws_envelop_with_invalid_utf8_encoding_payload() ->
    ?assertEqual({error, {invalid_payload, #{position => {1,9}, reason => invalid_escape_sequence}}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIn0.eyJhbGciOiJceEUwXHg4MFx4ODAifQ.">>, none, <<>>)).

decode_compact_in_jws_enevlop_with_mismatch_header_replicated_claims() ->
    ?assertMatch({error, {invalid_claim, iat, header_replicate_mismatch}},
                 jose_jwt:decode_compact(<<"eyJhbGciOiJub25lIiwiaWF0IjoxMjN9.eyJqdGkiOiJmb28iLCJpYXQiOjB9.">>, none, <<>>)).

decode_compact_with_jwe_envelop_test_() ->
    [].
