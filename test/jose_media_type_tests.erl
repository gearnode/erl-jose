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

-module(jose_media_type_tests).

-include_lib("eunit/include/eunit.hrl").

parse_test_() ->
    MediaType0 = #{type => <<"application">>, subtype => <<"json">>,
                   parameters => #{<<"charset">> => <<"UTF-8">>,
                                   <<"version">> => <<"v1">>}},
    MediaType1 = #{type => <<"application">>, subtype => <<"json">>,
                   parameters => #{}},
    [?_assertMatch({ok, MediaType0}, jose_media_type:parse(<<"application/json; version=v1; charset=\"UTF-8\"">>)),
     ?_assertMatch({ok, MediaType1}, jose_media_type:parse(<<"application/json">>)),
     ?_assertMatch({ok, MediaType1}, jose_media_type:parse(<<"application/json;">>))].

serialize_test_() ->
    MediaType0 = #{type => <<"application">>, subtype => <<"json">>,
                   parameters => #{<<"charset">> => <<"UTF-8">>,
                                   <<"version">> => <<"v1">>}},
    MediaType1 = #{type => <<"application">>, subtype => <<"json">>,
                   parameters => #{}},
    [?_assertEqual(<<"application/json;charset=\"UTF-8\";version=\"v1\"">>, jose_media_type:serialize(MediaType0)),
     ?_assertEqual(<<"application/json">>, jose_media_type:serialize(MediaType1))].
