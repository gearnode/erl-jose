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

-export([encode64/1, encode64url/1, encode16/1]).

-spec encode64(Bin) -> Base64 when
      Bin :: binary(),
      Base64 :: binary().
encode64(Bin) ->
    encode64(Bin, <<>>).

-spec encode64(Bin, Base64) -> Base64 when
      Bin :: binary(),
      Base64 :: binary().
encode64(<<>>, Acc) ->
    Acc;
encode64(<<A:6, B:6, C:6, D:6, Rest/binary>>, Acc) ->
    encode64(Rest, <<Acc/binary, (enc64(A)), (enc64(B)), (enc64(C)), (enc64(D))>>);
encode64(<<A:6, B:2>>, Acc) ->
    <<Acc/binary, (enc64(A)), (enc64(B bsl 4)), $=, $=>>;
encode64(<<A:6, B:6, C:4>>, Acc) ->
    <<Acc/binary, (enc64(A)), (enc64(B)), (enc64(C bsl 2)), $=>>.


-spec enc64(0..63) -> byte().
enc64(Char) when Char =< 25 ->
    Char + $A;
enc64(Char) when Char =< 51 ->
    Char + $a - 26;
enc64(Char) when Char =< 61 ->
    Char + $0 - 52;
enc64(62) ->
    $+;
enc64(63) ->
    $/.

-spec encode64url(Bin) -> Base64URL when
      Bin :: binary(),
      Base64URL :: binary().
encode64url(Bin) ->
    encode64url(Bin, <<>>).

-spec encode64url(Bin, Base64URL) -> Base64URL when
      Bin :: binary(),
      Base64URL :: binary().
encode64url(<<>>, Acc) ->
    Acc;
encode64url(<<A:6, B:6, C:6, D:6, Rest/binary>>, Acc) ->
    encode64url(Rest, <<Acc/binary, (enc64url(A)), (enc64url(B)), (enc64url(C)), (enc64url(D))>>);
encode64url(<<A:6, B:2>>, Acc) ->
    <<Acc/binary, (enc64url(A)), (enc64url(B bsl 4)), $=, $=>>;
encode64url(<<A:6, B:6, C:4>>, Acc) ->
    <<Acc/binary, (enc64url(A)), (enc64url(B)), (enc64url(C bsl 2)), $=>>.

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

-spec encode16(Bin) -> Base16 when
      Bin :: binary(),
      Base16 :: binary().
encode16(Bin) ->
    encode16(Bin, <<>>).

-spec encode16(Bin, Base16) -> Base16 when
      Bin :: binary(),
      Base16 :: binary().
encode16(<<>>, Acc) ->
    Acc;
encode16(<<A:4, B:4, Rest/binary>>, Acc) ->
    encode16(Rest, <<Acc/binary, (enc16(A)), (enc16(B))>>).

-spec enc16(0..15) -> byte().
enc16(Char) when Char =< 9 ->
    Char + $0;
enc16(Char) when Char =< 15 ->
    Char + $A - 10.
