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

-module(jose_base).

-export([encode64url/1, encode64url/2]).

-spec encode64url(Bin) -> Base64URL when
      Bin :: binary(),
      Base64URL :: binary().
encode64url(Bin) ->
    encode64url(Bin, true, <<>>).

-spec encode64url(Bin, Opts) -> Base64URL when
      Bin :: binary(),
      Opts :: map(),
      Base64URL :: binary().
encode64url(Bin, Opts) ->
    Padding = maps:get(padding, Opts, true),
    encode64url(Bin, Padding, <<>>).

-spec encode64url(Bin, WithPadding, Base64URL) -> Base64URL when
      Bin :: binary(),
      WithPadding :: boolean(),
      Base64URL :: binary().
encode64url(<<>>, _Padding, Acc) ->
    Acc;
encode64url(<<A:6, B:6, C:6, D:6, Rest/binary>>, Padding, Acc) ->
    encode64url(Rest, Padding, <<Acc/binary, (enc64url(A)), (enc64url(B)), (enc64url(C)), (enc64url(D))>>);
encode64url(<<A:6, B:2>>, true, Acc) ->
    <<Acc/binary, (enc64url(A)), (enc64url(B bsl 4)), $=, $=>>;
encode64url(<<A:6, B:6, C:4>>, true, Acc) ->
    <<Acc/binary, (enc64url(A)), (enc64url(B)), (enc64url(C bsl 2)), $=>>;
encode64url(<<A:6, B:2>>, false, Acc) ->
    <<Acc/binary, (enc64url(A)), (enc64url(B bsl 4))>>;
encode64url(<<A:6, B:6, C:4>>, false, Acc) ->
    <<Acc/binary, (enc64url(A)), (enc64url(B)), (enc64url(C bsl 2))>>.

-spec enc64url(0..63) -> byte().
enc64url(Char) when Char =< 25 ->
    Char + $A;
enc64url(Char) when Char =< 51 ->
    Char + $a - 26;
enc64url(Char) when Char =< 61 ->
    Char + $0 - 52;
enc64url(62) ->
    $-;
enc64url(63) ->
    $_.
