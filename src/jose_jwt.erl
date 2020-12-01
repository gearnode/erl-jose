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
         encode/4]).

-export_type([header/0,
              payload/0,
              string_or_uri/0]).

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
                    exp => calendar:datetime(),
                    nbf => calendar:datetime(),
                    iat => calendar:datetime(),
                    jti => binary()}.

-type payload() :: #{iss => string_or_uri(),
                     sub => string_or_uri(),
                     aud => [string_or_uri()] | string_or_uri(),
                     exp => calendar:datetime(),
                     nbf => calendar:datetime(),
                     iat => calendar:datetime(),
                     jti => binary()}.

-type string_or_uri() :: binary() | uri:uri().

-spec reserved_header_parameter_names() -> [jose:header_parameter_name()].
reserved_header_parameter_names() ->
    [<<"alg">>, <<"jku">>, <<"jwk">>, <<"kid">>,
     <<"x5u">>, <<"x5c">>, <<"x5t">>, <<"x5t#S256">>,
     <<"typ">>, <<"cty">>, <<"crit">>, <<"iss">>, <<"aud">>,
     <<"exp">>, <<"nbf">>, <<"iat">>, <<"jti">>].

-spec encode(header(), payload(), jose_jwa:alg(), public_key:private_key()) -> binary().
encode(Header0, Payload0, Alg, PrivKey) ->
    Header = maps:fold(fun serialize_claim/3, #{}, Header0),
    Payload = json:serialize(maps:fold(fun serialize_claim/3, #{}, Payload0), #{return_binary => true}),
    jose_jws:encode_compact(Header, Payload, Alg, PrivKey).

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
serialize_claim(exp, Value0, Acc) ->
    Value = calendar:datetime_to_gregorian_seconds(Value0) - ?EPOCH,
    Acc#{<<"exp">> => Value};
serialize_claim(nbf, Value0, Acc) ->
    Value = calendar:datetime_to_gregorian_seconds(Value0) - ?EPOCH,
    Acc#{<<"nbf">> => Value};
serialize_claim(iat, Value0, Acc) ->
    Value = calendar:datetime_to_gregorian_seconds(Value0) - ?EPOCH,
    Acc#{<<"iat">> => Value};
serialize_claim(jti, Value, Acc) when is_binary(Value) ->
    Acc#{<<"jti">> => Value};
serialize_claim(jti, _Value, _Acc) ->
    erlang:error(jti_claim_invalid_value);
serialize_claim(Key, Value, Acc) ->
    Acc#{Key => Value}.
