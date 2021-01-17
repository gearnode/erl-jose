%% Copyright (c) 2020-2021 Bryan Frimin <bryan@frimin.fr>.
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

-module(jose_media_type).

-export([parse/1, serialize/1]).

-export_type([media_type/0,
              attribute/0,
              value/0]).

-type media_type() :: #{type := binary(),
                        subtype := binary(),
                        parameters => #{attribute() => value()}}.

-type attribute() :: binary().
-type value() :: binary().

-spec serialize(media_type()) -> binary().
serialize(MediaType) ->
    Type = maps:get(type, MediaType),
    SubType = maps:get(subtype, MediaType),
    Parameters = maps:fold(fun (K, V, Acc) ->
                                   <<Acc/binary, $;, K/binary, $=, $", V/binary, $">>
                           end, <<>>, maps:get(parameters, MediaType, #{})),
    case Parameters of
        <<>> ->
            <<Type/binary, $/, SubType/binary>>;
        _Else ->
            <<Type/binary, $/, SubType/binary, Parameters/binary>>
    end.

-spec parse(binary()) -> {ok, media_type()} | {error, term()}.
parse(Bin) ->
    {Type0, Parameters0} = case binary:split(Bin, <<$;>>) of
                               [P1, P2] -> {P1, P2};
                               [P1] -> {P1, <<>>}
                           end,
    try
        {Type, SubType} = parse_type(Type0),
        Parameters = parse_parameters(Parameters0),
        MediaType = #{type => Type, subtype => SubType, parameters => Parameters},
        {ok, MediaType}

    catch
        throw:{error, Reason} ->
            {error, Reason}
    end.

-spec parse_type(binary()) -> {binary(), binary()}.
parse_type(Bin) ->
    case binary:split(Bin, <<$/>>) of
        [Type, SubType] ->
            validate_naming(Type),
            validate_naming(SubType),
            {Type, SubType};
        _Else ->
            throw({error, invalid_format})
    end.

-spec parse_parameters(binary()) -> #{attribute() => value()}.
parse_parameters(Bin) ->
    parse_parameters(Bin, #{}).

-spec parse_parameters(binary(), map()) -> #{attribute() => value()}.
parse_parameters(<<>>, Acc) ->
    Acc;
parse_parameters(Bin, Acc) ->
    {Name, Rest0} = parse_parameter_name(Bin),
    {Value, Rest} = parse_parameter_value(Rest0),
    parse_parameters(Rest, Acc#{Name => Value}).

-spec parse_parameter_name(binary()) -> {binary(), binary()}.
parse_parameter_name(Bin) ->
    case binary:split(Bin, <<$=>>) of
        [Name0, Rest] ->
            Name = string:trim(Name0),
            validate_naming(Name),
            {Name, Rest};
        _Else ->
            throw({error, invalid_format})
    end.

-spec parse_parameter_value(binary()) -> {binary(), binary()}.
parse_parameter_value(<<$", Bin/binary>>) ->
    {Value, Rest0} = case binary:split(Bin, <<$">>) of
                         [V, R] -> {V, R};
                         [V] -> {V, <<>>}
                     end,
    Rest = case binary:split(Rest0, <<$;>>) of
               [<<>>, P2] -> P2;
               [P1] -> P1
           end,
    {Value, Rest};
parse_parameter_value(Bin) ->
    {Value0, Rest} = case binary:split(Bin, <<$;>>) of
                        [P1, P2] -> {P1, P2};
                        [P1] -> {P1, <<>>}
                    end,
    Value = string:trim(Value0, trailing),
    validate_naming(Value),
    {Value, Rest}.

-spec validate_naming(binary()) -> ok.
validate_naming(<<>>) ->
    throw({error, invalid_format});
validate_naming(Bin) when byte_size(Bin) > 127 ->
    throw({error, invalid_format});
validate_naming(Bin) ->
    <<First, Rest/binary>> = Bin,
    validate_naming_first(First),
    validate_naming_rest(Rest),
    ok.

validate_naming_first(Char)
  when Char >= $A, Char =< $Z;
       Char >= $a, Char =< $z;
       Char >= $0, Char =< $9 ->
    ok;
validate_naming_first(_Char) ->
    throw({error, invalid_format}).

validate_naming_rest(<<>>) ->
    ok;
validate_naming_rest(<<Char, Rest/binary>>)
  when Char >= $A, Char =< $Z;
       Char >= $a, Char =< $z;
       Char >= $0, Char =< $9;
       Char == $!;
       Char == $#;
       Char == $$;
       Char == $&;
       Char == $-;
       Char == $^;
       Char == $_;
       Char == $.;
       Char == $+ ->
    validate_naming_rest(Rest);
validate_naming_rest(_Bin) ->
    throw({error, invalid_format}).
