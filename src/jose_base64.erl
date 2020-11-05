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

-module(jose_base64).

-export([encode/1, decode/1]).

-spec decode(binary()) -> {ok, binary()} | {error, term()}.
decode(Bin) ->
    try decode(Bin, <<>>) of
        Result ->
            Result
    catch
        error:Reason ->
            {error, Reason}
    end.

-spec decode(binary(), binary()) -> {ok, binary()} | {error, term()}.
decode(<<>>, Acc) ->
    {ok, Acc};
decode(<<A:8, B:8, C:8, D:8, Rest/binary>>, Acc) ->
    A1 = dec64url(A),
    B1 = dec64url(B),
    C1 = dec64url(C),
    D1 = dec64url(D),
    Data = <<A1:6, B1:6, C1:6, D1:6>>,
    decode(Rest, <<Acc/binary, Data/binary>>);
decode(<<A:8, B:8>>, Acc) ->
    A1 = dec64url(A),
    B1 = dec64url(B) bsr 4,
    Data = <<A1:6, B1:2>>,
    decode(<<>>, <<Acc/binary, Data/binary>>);
decode(<<A:8, B:8, C:8>>, Acc) ->
    A1 = dec64url(A),
    B1 = dec64url(B),
    C1 = dec64url(C) bsr 2,
    Data = <<A1:6, B1:6, C1:4>>,
    decode(<<>>, <<Acc/binary, Data/binary>>);
decode(Data, _) ->
    {error, {invalid_data, Data}}.

-spec dec64url($A..$Z | $a..$z | $0..$9 | $- | $_) -> 0..63.
dec64url(Char) when Char >= $A, Char =< $Z ->
    Char - $A;
dec64url(Char) when Char >= $a, Char =< $z ->
    Char - $a + 26;
dec64url(Char) when Char >= $0, Char =< $9 ->
    Char - $0 + 52;
dec64url($-) ->
    62;
dec64url($_) ->
    63;
dec64url(Char) ->
    error({invalid_base64_char, Char}).

-spec encode(binary()) -> binary().
encode(Bin) ->
    encode(Bin, <<>>).

-spec encode(binary(), binary()) -> binary().
encode(<<>>, Acc) ->
    Acc;
encode(<<A:6, B:6, C:6, D:6, Rest/binary>>, Acc) ->
    encode(Rest, <<Acc/binary, (enc64url(A)), (enc64url(B)), (enc64url(C)), (enc64url(D))>>);
encode(<<A:6, B:2>>, Acc) ->
    <<Acc/binary, (enc64url(A)), (enc64url(B bsl 4))>>;
encode(<<A:6, B:6, C:4>>, Acc) ->
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
