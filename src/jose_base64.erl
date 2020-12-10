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

-export([encodeurl/1,
         encodeurl/2,
         encode/1,
         encode/2,
         decodeurl/1,
         decodeurl/2,
         decode/1,
         decode/2]).

-export_type([options/0]).

-type options() :: #{padding => boolean()}.

-spec decodeurl(binary()) -> {ok, binary()} | {error, term()}.
decodeurl(Bin) ->
    decodeurl(Bin, #{}).

-spec decodeurl(binary(), options()) -> {ok, binary()} | {error, term()}.
decodeurl(Bin, Options) ->
    try decodeurl(Bin, Options, <<>>) of
        Result ->
            Result
    catch
        error:Reason ->
            {error, Reason}
    end.

-spec decodeurl(binary(), options(), binary()) -> {ok, binary()} | {error, term()}.
decodeurl(<<>>, _Options, Acc) ->
    {ok, Acc};
decodeurl(<<_A:8, _B:8, _C:8, $=:8>>, _Options = #{padding := false}, _Acc) ->
    {error, invalid_encoding};
decodeurl(<<_A:8, _B:8, $=:8, $=:8>>, _Options = #{padding := false}, _Acc) ->
    {error, invalid_encoding};
decodeurl(<<A:8, B:8, C:8>>, Options =  #{padding := false}, Acc) ->
    A1 = dec64url(A),
    B1 = dec64url(B),
    C1 = dec64url(C) bsr 2,
    Data = <<A1:6, B1:6, C1:4>>,
    decodeurl(<<>>, Options, <<Acc/binary, Data/binary>>);
decodeurl(<<A:8, B:8>>, Options = #{padding := false}, Acc) ->
    A1 = dec64url(A),
    B1 = dec64url(B) bsr 4,
    Data = <<A1:6, B1:2>>,
    decodeurl(<<>>, Options, <<Acc/binary, Data/binary>>);
decodeurl(<<A:8, B:8, $=:8, $=:8>>, Options, Acc) ->
    A1 = dec64url(A),
    B1 = dec64url(B) bsr 4,
    Data = <<A1:6, B1:2>>,
    decodeurl(<<>>, Options, <<Acc/binary, Data/binary>>);
decodeurl(<<A:8, B:8, C:8, $=:8>>, Options, Acc) ->
    A1 = dec64url(A),
    B1 = dec64url(B),
    C1 = dec64url(C) bsr 2,
    Data = <<A1:6, B1:6, C1:4>>,
    decodeurl(<<>>, Options, <<Acc/binary, Data/binary>>);
decodeurl(<<A:8, B:8, C:8, D:8, Rest/binary>>, Options, Acc) ->
    A1 = dec64url(A),
    B1 = dec64url(B),
    C1 = dec64url(C),
    D1 = dec64url(D),
    Data = <<A1:6, B1:6, C1:6, D1:6>>,
    decodeurl(Rest, Options, <<Acc/binary, Data/binary>>);
decodeurl(Data, _, _) ->
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

-spec decode(binary()) -> {ok, binary()} | {error, term()}.
decode(Bin) ->
    decode(Bin, #{}).

-spec decode(binary(), options()) -> {ok, binary()} | {error, term()}.
decode(Bin, Options) ->
    try decode(Bin, Options, <<>>) of
        Result ->
            Result
    catch
        error:Reason ->
            {error, Reason}
    end.

-spec decode(binary(), options(), binary()) -> {ok, binary()} | {error, term()}.
decode(<<>>, _Options, Acc) ->
    {ok, Acc};
decode(<<_A:8, _B:8, _C:8, $=:8>>, _Options = #{padding := false}, _Acc) ->
    {error, invalid_encoding};
decode(<<_A:8, _B:8, $=:8, $=:8>>, _Options = #{padding := false}, _Acc) ->
    {error, invalid_encoding};
decode(<<A:8, B:8, C:8>>, Options = #{padding := false}, Acc) ->
    A1 = dec64(A),
    B1 = dec64(B),
    C1 = dec64(C) bsr 2,
    Data = <<A1:6, B1:6, C1:4>>,
    decode(<<>>, Options, <<Acc/binary, Data/binary>>);
decode(<<A:8, B:8>>, Options = #{padding := false}, Acc) ->
    A1 = dec64(A),
    B1 = dec64(B) bsr 4,
    Data = <<A1:6, B1:2>>,
    decode(<<>>, Options, <<Acc/binary, Data/binary>>);
decode(<<A:8, B:8, $=:8, $=:8>>, Options, Acc) ->
    A1 = dec64(A),
    B1 = dec64(B) bsr 4,
    Data = <<A1:6, B1:2>>,
    decode(<<>>, Options, <<Acc/binary, Data/binary>>);
decode(<<A:8, B:8, C:8, $=:8>>, Options, Acc) ->
    A1 = dec64(A),
    B1 = dec64(B),
    C1 = dec64(C) bsr 2,
    Data = <<A1:6, B1:6, C1:4>>,
    decode(<<>>, Options, <<Acc/binary, Data/binary>>);
decode(<<A:8, B:8, C:8, D:8, Rest/binary>>, Options, Acc) ->
    A1 = dec64(A),
    B1 = dec64(B),
    C1 = dec64(C),
    D1 = dec64(D),
    Data = <<A1:6, B1:6, C1:6, D1:6>>,
    decode(Rest, Options, <<Acc/binary, Data/binary>>);
decode(Data, _, _) ->
    {error, {invalid_data, Data}}.

-spec dec64($A..$Z | $a..$z | $0..$9 | $- | $_) -> 0..63.
dec64(Char) when Char >= $A, Char =< $Z ->
    Char - $A;
dec64(Char) when Char >= $a, Char =< $z ->
    Char - $a + 26;
dec64(Char) when Char >= $0, Char =< $9 ->
    Char - $0 + 52;
dec64($+) ->
    62;
dec64($/) ->
    63;
dec64(Char) ->
    error({invalid_base64_char, Char}).

-spec encode(binary()) -> binary().
encode(Bin) ->
    encode(Bin, #{}).

-spec encode(binary(), options()) -> binary().
encode(Bin, Options) ->
    encode(Bin, Options, <<>>).

-spec encode(binary(), options(), binary()) -> binary().
encode(<<>>, _Options, Acc) ->
    Acc;
encode(<<A:6, B:6, C:6, D:6, Rest/binary>>, Options, Acc) ->
    encode(Rest, Options, <<Acc/binary, (enc64(A)), (enc64(B)), (enc64(C)), (enc64(D))>>);
encode(<<A:6, B:2>>, #{padding := false}, Acc) ->
    <<Acc/binary, (enc64(A)), (enc64(B bsl 4))>>;
encode(<<A:6, B:6, C:4>>, #{padding := false}, Acc) ->
    <<Acc/binary, (enc64(A)), (enc64(B)), (enc64(C bsl 2))>>;
encode(<<A:6, B:2>>, _Options, Acc) ->
    <<Acc/binary, (enc64(A)), (enc64(B bsl 4)), $=, $=>>;
encode(<<A:6, B:6, C:4>>, _Options, Acc) ->
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

-spec encodeurl(binary()) -> binary().
encodeurl(Bin) ->
    encodeurl(Bin, #{}).

-spec encodeurl(binary(), options()) -> binary().
encodeurl(Bin, Options) ->
    encodeurl(Bin, Options, <<>>).

-spec encodeurl(binary(), options(), binary()) -> binary().
encodeurl(<<>>, _Options, Acc) ->
    Acc;
encodeurl(<<A:6, B:6, C:6, D:6, Rest/binary>>, Options, Acc) ->
    encodeurl(Rest, Options, <<Acc/binary, (enc64url(A)), (enc64url(B)), (enc64url(C)), (enc64url(D))>>);
encodeurl(<<A:6, B:2>>, #{padding := false}, Acc) ->
    <<Acc/binary, (enc64url(A)), (enc64url(B bsl 4))>>;
encodeurl(<<A:6, B:6, C:4>>, #{padding := false}, Acc) ->
    <<Acc/binary, (enc64url(A)), (enc64url(B)), (enc64url(C bsl 2))>>;
encodeurl(<<A:6, B:2>>, _Options, Acc) ->
    <<Acc/binary, (enc64url(A)), (enc64url(B bsl 4)), $=, $=>>;
encodeurl(<<A:6, B:6, C:4>>, _Options, Acc) ->
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
