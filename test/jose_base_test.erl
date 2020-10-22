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

-module(jose_base_test).

-include_lib("eunit/include/eunit.hrl").

encode64_test_() ->
    [?_assertEqual(<<>>, jose_base:encode64(<<>>)),
     ?_assertEqual(<<"Zg==">>, jose_base:encode64(<<"f">>)),
     ?_assertEqual(<<"Zm8=">>, jose_base:encode64(<<"fo">>)),
     ?_assertEqual(<<"Zm9v">>, jose_base:encode64(<<"foo">>)),
     ?_assertEqual(<<"Zm9vYg==">>, jose_base:encode64(<<"foob">>)),
     ?_assertEqual(<<"Zm9vYmE=">>, jose_base:encode64(<<"fooba">>)),
     ?_assertEqual(<<"Zm9vYmFy">>, jose_base:encode64(<<"foobar">>))].

encode64url_test_() ->
    [?_assertEqual(<<>>, jose_base:encode64url(<<>>)),
     ?_assertEqual(<<"Zg==">>, jose_base:encode64url(<<"f">>)),
     ?_assertEqual(<<"Zm8=">>, jose_base:encode64url(<<"fo">>)),
     ?_assertEqual(<<"Zm9v">>, jose_base:encode64url(<<"foo">>)),
     ?_assertEqual(<<"Zm9vYg==">>, jose_base:encode64url(<<"foob">>)),
     ?_assertEqual(<<"Zm9vYmE=">>, jose_base:encode64url(<<"fooba">>)),
     ?_assertEqual(<<"Zm9vYmFy">>, jose_base:encode64url(<<"foobar">>))].

encode16_test_() ->
    [?_assertEqual(<<>>, jose_base:encode16(<<>>)),
     ?_assertEqual(<<"66">>, jose_base:encode16(<<"f">>)),
     ?_assertEqual(<<"666F">>, jose_base:encode16(<<"fo">>)),
     ?_assertEqual(<<"666F6F">>, jose_base:encode16(<<"foo">>)),
     ?_assertEqual(<<"666F6F62">>, jose_base:encode16(<<"foob">>)),
     ?_assertEqual(<<"666F6F6261">>, jose_base:encode16(<<"fooba">>)),
     ?_assertEqual(<<"666F6F626172">>, jose_base:encode16(<<"foobar">>))].
