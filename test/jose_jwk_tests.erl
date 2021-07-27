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

-module(jose_jwk_tests).

-include_lib("eunit/include/eunit.hrl").

decode_empty_json_object_test() ->
  ?assertEqual({error,{missing_parameter,kty}},
               jose_jwk:decode(<<"{}">>)).

decode_json_array_test() ->
  ?assertEqual({error, invalid_format},
               jose_jwk:decode(<<"[]">>)).

decode_empty_map_test() -> 
  ?assertEqual({error,{missing_parameter,kty}},
               jose_jwk:decode(#{})).

decode_term_test() ->
  ?assertEqual({error, invalid_format},
               jose_jwk:decode([])),
  ?assertEqual({error, invalid_format},
               jose_jwk:decode(foo)),
  ?assertEqual({error, invalid_format},
               jose_jwk:decode("hello")),
  ?assertEqual({error, invalid_format},
               jose_jwk:decode(1)).
  
decode_emtpy_bin_test() ->
  ?assertEqual({error,
                {invalid_format,
                 #{position => {1,1}, reason => no_value}}},
               jose_jwk:decode(<<>>)).

decode_jwk_with_not_supported_kty_test() ->
  ?assertEqual({error,
                {invalid_parameter,
                 {unsupported,<<"foobar">>}, kty}},
               jose_jwk:decode(#{<<"kty">> => <<"foobar">>})).
