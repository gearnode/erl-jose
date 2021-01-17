%% Copyright (c) 2020-2021 Bryan Frimin <bryan@frimin.fr>.
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

-module(jose_base64url_tests).

-include_lib("eunit/include/eunit.hrl").

encodeurl_without_padding_test_() ->
  [?_assertEqual(<<>>,
                 jose_base64url:encode(<<>>)),
   ?_assertEqual(<<"Zg">>,
                 jose_base64url:encode(<<"f">>,
                                       #{padding => false})),
   ?_assertEqual(<<"Zm8">>,
                 jose_base64url:encode(<<"fo">>,
                                       #{padding => false})),
   ?_assertEqual(<<"Zm9v">>,
                 jose_base64url:encode(<<"foo">>,
                                       #{padding => false})),
   ?_assertEqual(<<"Zm9vYg">>,
                 jose_base64url:encode(<<"foob">>,
                                       #{padding => false})),
   ?_assertEqual(<<"Zm9vYmE">>,
                 jose_base64url:encode(<<"fooba">>,
                                       #{padding => false})),
   ?_assertEqual(<<"Zm9vYmFy">>,
                 jose_base64url:encode(<<"foobar">>,
                                       #{padding => false}))].

encodeurl_with_padding_test_() ->
  [?_assertEqual(<<>>,
                 jose_base64url:encode(<<>>)),
   ?_assertEqual(<<"Zg==">>,
                 jose_base64url:encode(<<"f">>)),
   ?_assertEqual(<<"Zm8=">>,
                 jose_base64url:encode(<<"fo">>)),
   ?_assertEqual(<<"Zm9v">>,
                 jose_base64url:encode(<<"foo">>)),
   ?_assertEqual(<<"Zm9vYg==">>,
                 jose_base64url:encode(<<"foob">>)),
   ?_assertEqual(<<"Zm9vYmE=">>,
                 jose_base64url:encode(<<"fooba">>)),
   ?_assertEqual(<<"Zm9vYmFy">>,
                 jose_base64url:encode(<<"foobar">>))].

decodeurl_without_padding_test_() ->
  [?_assertEqual({ok, <<>>},
                 jose_base64url:decode(<<>>, #{padding => false})),
   ?_assertEqual({ok, <<"f">>},
                 jose_base64url:decode(<<"Zg">>, #{padding => false})),
   ?_assertEqual({ok, <<"fo">>},
                 jose_base64url:decode(<<"Zm8">>, #{padding => false})),
   ?_assertEqual({ok, <<"foo">>},
                 jose_base64url:decode(<<"Zm9v">>, #{padding => false})),
   ?_assertEqual({ok, <<"foob">>},
                 jose_base64url:decode(<<"Zm9vYg">>, #{padding => false})),
   ?_assertEqual({ok, <<"fooba">>},
                 jose_base64url:decode(<<"Zm9vYmE">>, #{padding => false})),
   ?_assertEqual({ok, <<"foobar">>},
                 jose_base64url:decode(<<"Zm9vYmFy">>, #{padding => false}))].

decodeurl_with_padding_test_() ->
  [?_assertEqual({ok, <<>>},
                 jose_base64url:decode(<<>>)),
   ?_assertEqual({ok, <<"f">>},
                 jose_base64url:decode(<<"Zg==">>)),
   ?_assertEqual({ok, <<"fo">>},
                 jose_base64url:decode(<<"Zm8=">>)),
   ?_assertEqual({ok, <<"foo">>},
                 jose_base64url:decode(<<"Zm9v">>)),
   ?_assertEqual({ok, <<"foob">>},
                 jose_base64url:decode(<<"Zm9vYg==">>)),
   ?_assertEqual({ok, <<"fooba">>},
                 jose_base64url:decode(<<"Zm9vYmE=">>)),
   ?_assertEqual({ok, <<"foobar">>},
                 jose_base64url:decode(<<"Zm9vYmFy">>))].
