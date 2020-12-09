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

-module(jose_jwt).

-define(EPOCH, calendar:datetime_to_gregorian_seconds({{1970, 1, 1}, {0, 0, 0}})).

-export([reserved_header_parameter_names/0,
         encode_compact/3,
         encode_compact/4,
         decode_compact/3,
         decode_compact/4]).

-export_type([jwt/0,
              header/0,
              payload/0,
              numeric_date/0,
              string_or_uri/0,
              encode_options/0,
              decode_options/0]).

-type jwt() :: {header(), payload()}.

-type header() :: #{alg => jose_jwa:alg(),
                    jku => uri:uri(),
                    jwk => jose_jwk:jwk(),
                    kid => jose:kid(),
                    x5u => uri:uri(),
                    x5c => [jose:certificate()],
                    x5t => jose:certificate_thumbprint(),
                    'x5t#S256' => jose:certificate_thumbprint(),
                    typ => jose_media_type:media_type(),
                    cty => jose_media_type:media_type(),
                    b64 => boolean(),
                    crit => [jose:header_parameter_name()],
                    iss => string_or_uri(),
                    sub => string_or_uri(),
                    aud => [string_or_uri()] | string_or_uri(),
                    exp => numeric_date(),
                    nbf => numeric_date(),
                    iat => numeric_date(),
                    jti => binary()}.

-type payload() :: #{iss => string_or_uri(),
                     sub => string_or_uri(),
                     aud => [string_or_uri()] | string_or_uri(),
                     exp => numeric_date(),
                     nbf => numeric_date(),
                     iat => numeric_date(),
                     jti => binary()}.

-type numeric_date() :: integer().
-type string_or_uri() :: binary() | uri:uri().

-type encode_options() :: #{header_claims => [atom() | binary()]}.
-type decode_options() :: #{aud => string_or_uri()}.


-spec reserved_header_parameter_names() -> [jose:header_parameter_name()].
reserved_header_parameter_names() ->
    [<<"alg">>, <<"jku">>, <<"jwk">>, <<"kid">>,
     <<"x5u">>, <<"x5c">>, <<"x5t">>, <<"x5t#S256">>,
     <<"typ">>, <<"cty">>, <<"crit">>, <<"iss">>, <<"aud">>,
     <<"exp">>, <<"nbf">>, <<"iat">>, <<"jti">>].

-spec encode_compact(jwt(), jose_jwa:alg(), jose_jwa:verify_key()) -> binary().
encode_compact(JWT, Alg, PrivKey) ->
    encode_compact(JWT, Alg, PrivKey, #{}).

-spec encode_compact(jwt(), jose_jwa:alg(), jose_jwa:verify_key(), encode_options()) -> binary().
encode_compact({Header0, Payload0}, Alg, PrivKey, Options) ->
    Header1 = case maps:get(header_claims, Options, []) of
                  [] ->
                      Header0;
                  Claims ->
                      maps:merge(maps:with(Claims, Payload0), Header0)
              end,
    Header = maps:fold(fun serialize_claim/3, #{}, Header1),
    Payload = json:serialize(maps:fold(fun serialize_claim/3, #{}, Payload0), #{return_binary => true}),
    jose_jws:encode_compact({Header, Payload}, Alg, PrivKey).

-spec serialize_claim(json:key(), term(), map()) -> map().
serialize_claim(iss, Value, Acc) when is_binary(Value) ->
    Acc#{<<"iss">> => Value};
serialize_claim(iss, Value0, Acc) ->
    Value = uri:serialize(Value0),
    Acc#{<<"iss">> => Value};
serialize_claim(sub, Value, Acc) when is_binary(Value) ->
    Acc#{<<"sub">> => Value};
serialize_claim(sub, Value0, Acc) ->
    Value = uri:serialize(Value0),
    Acc#{<<"sub">> => Value};
serialize_claim(aud, Value0, Acc) when is_list(Value0) ->
    F = fun (X) when is_binary(X) -> X; (X) -> uri:serialize(X) end,
    Value = lists:map(F, Value0),
    Acc#{<<"aud">> => Value};
serialize_claim(aud, Value, Acc) when is_binary(Value) ->
    Acc#{<<"aud">> => Value};
serialize_claim(aud, Value0, Acc) ->
    Value = uri:serialize(Value0),
    Acc#{<<"aud">> => Value};
serialize_claim(exp, Value, Acc) when is_integer(Value) ->
    Acc#{<<"exp">> => Value};
serialize_claim(exp, _, _) ->
    erlang:error(exp_claim_invalid_value);
serialize_claim(nbf, Value, Acc) when is_integer(Value) ->
    Acc#{<<"nbf">> => Value};
serialize_claim(nbf, _, _) ->
    erlang:error(nbf_claim_invalid_value);
serialize_claim(iat, Value, Acc) when is_integer(Value) ->
    Acc#{<<"iat">> => Value};
serialize_claim(iat, _, _) ->
    erlang:error(iat_claim_invalid_value);
serialize_claim(jti, Value, Acc) when is_binary(Value) ->
    Acc#{<<"jti">> => Value};
serialize_claim(jti, _Value, _Acc) ->
    erlang:error(jti_claim_invalid_value);
serialize_claim(Key, Value, Acc) ->
    Acc#{Key => Value}.

-spec decode_compact(Token :: binary(), jose_jwa:alg(), public_key:private_key()) -> {ok, jwt()} | {error, term()}.
decode_compact(Token, Alg, Key) ->
    decode_compact(Token, Alg, Key, #{}).

-spec decode_compact(Token :: binary(), jose_jwa:alg(), public_key:private_key(), decode_options())
            -> {ok, jwt()} | {error, term()}.
decode_compact(Bin, Alg,Key, Options) ->
    case binary:split(Bin, <<$.>>, [global]) of
        [_,_,_] ->
            case jose_jws:decode_compact(Bin, Alg, Key, Options) of
                {ok, {Header0, Payload0}} ->
                    case json:parse(Payload0) of
                        {ok, Data} ->
                            try
                                Payload = maps:fold(fun parse_claim/3, #{}, Data),
                                Header = maps:fold(fun parse_claim/3, #{}, Header0),
                                ensure_header_replicated_claims_match({Header, Payload}),
                                validate_claims(Payload, Options),
                                {ok, {Header, Payload}}
                            catch
                                throw:{error, Reason} ->
                                    {error, Reason}
                            end;
                        {error, Reason} ->
                            {error, Reason}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        [_,_,_,_,_] ->
            {error, jwe_not_supported};
        _Else ->
            {error, invalid_format}
    end.

-spec parse_claim(json:key(), json:value(), payload()) -> payload().
parse_claim(<<"iss">>, Value0, Acc) when is_binary(Value0) ->
    case parse_string_or_uri(Value0) of
        {ok, Value} -> Acc#{iss => Value};
        {error, Reason} -> throw({error, {invalid_claim, iss, Reason}})
    end;
parse_claim(<<"iss">>, _, _) ->
    throw({error, {invalid_claim, iss, invalid_format}});
parse_claim(<<"sub">>, Value0, Acc) when is_binary(Value0) ->
    case parse_string_or_uri(Value0) of
        {ok, Value} -> Acc#{sub => Value};
        {error, Reason} -> throw({error, {invalid_claim, sub, Reason}})
    end;
parse_claim(<<"sub">>, _, _) ->
    throw({error, {invalid_claim, sub, invalid_format}});
parse_claim(<<"aud">>, Values0, Acc) when is_list(Values0) ->
    F =
        fun (Value0) ->
                case parse_string_or_uri(Value0) of
                    {ok, Value} ->
                        Value;
                    {error, Reason} ->
                        throw({error, {invalid_claim, aud, Reason}})
                end
        end,
    Values = lists:map(F, Values0),
    Acc#{aud => Values};
parse_claim(<<"aud">>, Value0, Acc) when is_binary(Value0) ->
    case parse_string_or_uri(Value0) of
        {ok, Value} -> Acc#{aud => Value};
        {error, Reason} -> throw({error, {invalid_claim, aud, Reason}})
    end;
parse_claim(<<"aud">>, _, _) ->
    throw({error, {invalid_claim, sub, invalid_format}});
parse_claim(<<"exp">>, Value, Acc) when is_integer(Value) ->
    Acc#{exp => Value};
parse_claim(<<"exp">>, _, _) ->
    throw({error, {invalid_claim, exp, invalid_format}});
parse_claim(<<"nbf">>, Value, Acc) when is_integer(Value) ->
    Acc#{nbf => Value};
parse_claim(<<"nbf">>, _, _) ->
    throw({error, {invalid_claim, exp, invalid_format}});
parse_claim(<<"iat">>, Value, Acc) when is_integer(Value) ->
    Acc#{iat => Value};
parse_claim(<<"iat">>, _, _) ->
    throw({error, {invalid_claim, nbf, invalid_format}});
parse_claim(<<"jti">>, Value, Acc) when is_binary(Value) ->
    Acc#{jti => Value};
parse_claim(<<"jti">>, _, _) ->
    throw({error, {invalid_claim, jti, invalid_format}});
parse_claim(Key, Value, Acc) ->
    Acc#{Key => Value}.

-spec parse_string_or_uri(term()) -> {ok, string_or_uri()} | {error, term()}.
parse_string_or_uri(Value0) when is_binary(Value0) ->
    case binary:split(Value0, <<$:>>) of
        [_, _] -> case uri:parse(Value0) of
                      {ok, Value} -> {ok, Value};
                      {error, Reason} -> {error, Reason}
                  end;
        [_] -> {ok, Value0}
    end;
parse_string_or_uri(_) ->
    {error, invalid_format}.

-spec ensure_header_replicated_claims_match(jwt()) -> ok.
ensure_header_replicated_claims_match({Header, Payload}) ->
    F = fun (K, V, _) ->
                case maps:is_key(K, Header) of
                    true ->
                        Value = maps:get(K, Header),
                        if V =:= Value -> ok;
                           true -> throw({error, {invalid_claim, K, header_replicate_mismatch}})
                        end;
                    false ->
                        ok
                end
        end,
    maps:fold(F, ok, Payload).

-spec validate_claims(payload(), decode_options()) -> ok.
validate_claims(Payload, Options) ->
    maps:fold(fun validate_claim/3, Options, Payload), ok.

-spec validate_claim(json:key(), json:value(), decode_options()) -> term().
validate_claim(aud, Values, Options) when is_list(Values)->
    case maps:is_key(aud, Options) of
        false ->
            throw({error, {invalid_claim, aud, mismatch}});
        true ->
            Aud = maps:get(aud, Options, inet:gethostname()),
            Match = fun(X) -> X =:= Aud end,
            case lists:any(Match, Values) of
                true -> Options;
                false -> throw({error, {invalid_claim, aud, mismatch}})
            end
    end;
validate_claim(aud, Value, Options) ->
    case maps:is_key(aud, Options) of
        false ->
            throw({error, {invalid_claim, aud, mismatch}});
        true ->
            Aud = maps:get(aud, Options, inet:gethostname()),
            if Aud =:= Value -> Options;
               true -> throw({error, {invalid_claim, aud, mismatch}})
            end
    end;
validate_claim(exp, Expiration, Options) ->
    Now = erlang:system_time(),
    if Expiration < Now -> Options;
       true -> throw({error, {invalid_claim, exp, not_valid_anymore}})
    end;
validate_claim(nbf, NotBefore, Options) ->
    Now = erlang:system_time(),
    if NotBefore > Now -> Options;
       true -> throw({error, {invalid_claim, nbf, not_valid_yet}})
    end;
validate_claim(K, V, Options) ->
    case maps:get(validate_claim, Options, none) of
        none -> Options;
        Func ->
            case Func(K, V) of
                ok -> Options;
                {error, Reason} -> throw({error, {invalid_claim, K, Reason}})
            end
    end.
