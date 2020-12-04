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

-module(jose_jws).

-export([reserved_header_parameter_names/0,
         encode_compact/3,
         encode_compact/4,
         decode_compact/3]).

-export_type([header/0,
              typ/0,
              cty/0,
              payload/0,
              compact/0,
              encode_options/0,
              decode_error_reason/0]).

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
                    crit => [jose:header_parameter_name()]}.

-type typ() :: binary().
-type cty() :: binary().
-type payload() :: binary().
-type compact() :: binary().

-type encode_options() :: map().

-type decode_error_reason() :: invalid_format
                             | {invalid_header, Key :: term(), Reason :: term()}
                             | {invalid_header, Reason :: term()}
                             | {invalid_payload, Reason :: term()}
                             | {invalid_signature, Reason :: term()}.

-spec reserved_header_parameter_names() -> [jose:header_parameter_name()].
reserved_header_parameter_names() ->
    [<<"alg">>, <<"jku">>, <<"jwk">>, <<"kid">>,
     <<"x5u">>, <<"x5c">>, <<"x5t">>, <<"x5t#S256">>,
     <<"typ">>, <<"cty">>, <<"crit">>].

-type jws() :: {header(), payload()}.

-spec encode_compact(jws(), jose_jwa:alg(), jose_jwa:sign_key()) ->
          compact().
encode_compact(JWS, Alg, Key) ->
    DefaultOptions = #{},
    encode_compact(JWS, Alg, Key, DefaultOptions).

-spec encode_compact(jws(), jose_jwa:alg(), jose_jwa:sign_key(), encode_options()) ->
          compact().
encode_compact({Header, Payload}, Alg, Key, _Options) ->
    EncodedHeader = serialize_header(Header),
    EncodedPayload = serialize_payload(Header, Payload),
    Message = <<EncodedHeader/binary, $., EncodedPayload/binary>>,
    Signature = jose_base64:encodeurl(jose_jwa:sign(Message, Alg, Key), #{padding => false}),
    <<Message/binary, $., Signature/binary>>.

-spec serialize_header(header()) -> binary().
serialize_header(Header) ->
    Object = maps:fold(fun serialize_header_parameter_name/3, #{}, Header),
    Data = json:serialize(Object, #{return_binary => true}),
    jose_base64:encodeurl(Data, #{padding => false}).

-spec serialize_header_parameter_name(json:key(), term(), map()) -> #{json:key() => json:value()}.
serialize_header_parameter_name(alg, Alg, Header) ->
    Header#{<<"alg">> => jose_jwa:encode_alg(Alg)};
serialize_header_parameter_name(jku, Value, Header) when is_binary(Value) ->
    Header#{<<"jku">> => Value};
serialize_header_parameter_name(jku, URI, Header) ->
    Value = uri:serialize(URI),
    Header#{<<"jku">> => Value};
serialize_header_parameter_name(jwk, JWK, Header) ->
    % TODO: serialize JWK with jose_jwk:serialize(...)
    Header#{<<"jwk">> => JWK};
serialize_header_parameter_name(kid, KId, Header) ->
    Header#{<<"kid">> => KId};
serialize_header_parameter_name(x5u, Value, Header) when is_binary(Value) ->
    Header#{<<"x5u">> => Value};
serialize_header_parameter_name(x5u, URI, Header) ->
    Value = uri:serialize(URI),
    Header#{<<"x5u">> => Value};
serialize_header_parameter_name(x5c, CertChain, Header) ->
    F = fun
            (X) when is_binary(X) ->
                jose_base64:encode(X);
            (X) ->
                jose_base64:encode(public_key:pkix_encode('OTPCertificate', X, otp))
        end,
    Value = lists:map(F, CertChain),
    Header#{<<"x5c">> => Value};
serialize_header_parameter_name(x5t, Fingerprint, Header) ->
    Value = jose_base64:encodeurl(Fingerprint),
    Header#{<<"x5t">> => Value};
serialize_header_parameter_name('x5t#S256', Fingerprint, Header) ->
    Value = jose_base64:encodeurl(Fingerprint),
    Header#{<<"x5t#S256">> => Value};
serialize_header_parameter_name(typ, Value, Header) when is_binary(Value) ->
    Header#{<<"typ">> => Value};
serialize_header_parameter_name(typ, MediaType, Header) ->
    Value = jose_media_type:serialize(MediaType),
    Header#{<<"typ">> => Value};
serialize_header_parameter_name(cty, Value, Header) when is_binary(Value) ->
    Header#{<<"cty">> => Value};
serialize_header_parameter_name(cty, MediaType, Header) ->
    Value = jose_media_type:serialize(MediaType),
    Header#{<<"cty">> => Value};
serialize_header_parameter_name(crit, Value, Header) ->
    Header#{<<"crit">> => Value};
serialize_header_parameter_name(Key, Value, Header) ->
    Header#{Key => Value}.

-spec serialize_payload(header(), payload()) -> binary().
serialize_payload(#{b64 := false} = _Header, Payload) ->
    Payload;
serialize_payload(_Header, Payload) ->
    jose_base64:encodeurl(Payload, #{padding => false}).

-spec decode_compact(compact(), jose_jwa:alg(), [jose_jwa:verify_key()] | jose_jwa:verify_key()) ->
          {ok, jws()} | {error, decode_error_reason()}.
decode_compact(Token, Alg, Key) when not is_list(Key) ->
    decode_compact(Token, Alg, [Key]);
decode_compact(Token, Alg, Keys0) ->
    try
        {P1, P2, P3} = parse_parts(Token),
        Header = decode_header(P1),
        Payload = decode_payload(Header, P2),
        Signature = decode_signature(P3),
        Message = <<P1/binary, $., P2/binary>>,

        CollectKeys = fun (A, B, C) -> collect_potential_verify_keys(A, B, C, Alg) end,
        VerifySig = fun (Key) -> jose_jwa:verify(Message, Signature, Alg, Key) end,

        Keys = maps:fold(CollectKeys, Keys0, Header),
        case lists:any(VerifySig, Keys) of
            true -> {ok, {Header, Payload}};
            false -> {error, invalid_signature}
        end
    catch
        throw:{error, Reason} ->
            {error, Reason}
    end.

-spec parse_parts(compact()) -> {binary(), binary(), binary()}.
parse_parts(Bin) ->
    case binary:split(Bin, <<$.>>, [global]) of
        [Header, Payload, Signature] ->
            {Header, Payload, Signature};
        _ ->
            throw({error, invalid_format})
    end.

-spec decode_header(binary()) -> header().
decode_header(Data0) ->
    case jose_base64:decodeurl(Data0, #{padding => false}) of
        {ok, Data} ->
            parse_header_object(Data);
        {error, Reason} ->
            throw({error, {invalid_header, Reason}})
    end.

-spec parse_header_object(binary()) -> header().
parse_header_object(Data) ->
    case json:parse(Data, #{duplicate_key_handling => error}) of
        {ok, Header} ->
            parse_header_parameter_names(Header);
        {error, Reason} ->
            throw({error, {invalid_header, Reason}})
    end.

-spec parse_header_parameter_names(map()) -> header().
parse_header_parameter_names(Header) ->
    maps:fold(fun parse_header_parameter_name/3, #{}, Header).

-spec parse_header_parameter_name(json:key(), json:value(), header()) ->
          #{json:key() => term()}.
parse_header_parameter_name(<<"alg">>, Value, Header) when is_binary(Value)->
    case jose_jwa:decode_alg(Value) of
        {ok, Alg} -> Header#{alg => Alg};
        {error, Reason} -> throw({error, {invalid_header, alg, Reason}})
    end;
parse_header_parameter_name(<<"alg">>, _Value, _Header) ->
    throw({error, {invalid_header, alg, invalid_format}});
parse_header_parameter_name(<<"jku">>, Value, Header) when is_binary(Value) ->
    case uri:parse(Value) of
        {ok, URI} ->
            Header#{jku => URI};
        {error, Reason} ->
            throw({error, {invalid_header, jku, Reason}})
    end;
parse_header_parameter_name(<<"jku">>, _Value, _Header) ->
    throw({error, {invalid_header, jku, invalid_format}});
parse_header_parameter_name(<<"kid">>, Value, Header) when is_binary(Value) ->
    Header#{kid => Value};
parse_header_parameter_name(<<"kid">>, _Valie, _Header) ->
    throw({error, {invalid_header, kid, invalid_format}});
parse_header_parameter_name(<<"x5u">>, Value, Header) when is_binary(Value)->
    case uri:parse(Value) of
        {ok, URI} ->
            Header#{x5u => URI};
        {error, Reason} ->
            throw({error, {invalid_header, x5u, Reason}})
    end;
parse_header_parameter_name(<<"x5u">>, _Value, _Header) ->
    throw({error, {invalid_header, x5u, invalid_format}});
parse_header_parameter_name(<<"x5c">>, [], _Header) ->
    throw({error, {invalid_header, x5c, invalid_format}});
parse_header_parameter_name(<<"x5c">>, Value, Header) when is_list(Value) ->
    Chain = parse_x5c_header_parameter_name(Value, []),
    Header#{x5c => Chain};
parse_header_parameter_name(<<"x5c">>, _Value, _Header) ->
    throw({error, {invalid_header, x5c, invalid_format}});
parse_header_parameter_name(<<"x5t">>, Value, Header) when is_binary(Value) ->
    case jose_base64:decodeurl(Value) of
        {ok, Thumbprint} ->
            Header#{x5t => Thumbprint};
        {error, Reason} ->
            throw({error, {invalid_header, x5t, Reason}})
    end;
parse_header_parameter_name(<<"x5t">>, _Value, _Header) ->
    throw({error, {invalid_header, x5t, invalid_format}});
parse_header_parameter_name(<<"x5t#S256">>, Value, Header) when is_binary(Value) ->
    case jose_base64:decodeurl(Value) of
        {ok, Thumbprint} ->
            Header#{'x5t#S256' => Thumbprint};
        {error, Reason} ->
            throw({error, {invalid_header, 'x5t#S256', Reason}})
    end;
parse_header_parameter_name(<<"x5t#S256">>, _Value, _Header) ->
    throw({error, {invalid_header, 'x5t#S256', invalid_format}});
parse_header_parameter_name(<<"typ">>, Value, Header) when is_binary(Value) ->
    case jose_media_type:parse(Value) of
        {ok, MediaType} ->
            Header#{typ => MediaType};
        {error, Reason} ->
            throw({error, {invalid_header, typ, Reason}})
    end;
parse_header_parameter_name(<<"typ">>, _Value, _Header) ->
    throw({error, {invalid_header, typ, invalid_format}});
parse_header_parameter_name(<<"cty">>, Value, Header) when is_binary(Value) ->
    case jose_media_type:parse(Value) of
        {ok, MediaType} ->
            Header#{cty => MediaType};
        {error, Reason} ->
            throw({error, {invalid_header, cty, Reason}})
    end;
parse_header_parameter_name(<<"cty">>, _Value, _Header) ->
    throw({error, {invalid_header, cty, invalid_format}});
parse_header_parameter_name(<<"crit">>, [], _Header) ->
    throw({error, {invalid_header, crit, invalid_format}});
parse_header_parameter_name(<<"crit">>, Value, Header) when is_list(Value) ->
    ReservedParameterNames = reserved_header_parameter_names() ++
        jose_jwa:reserved_header_parameter_names(),
    F = fun
            (X) when is_binary(X) ->
                case lists:member(X, ReservedParameterNames) of
                    true ->
                        throw({error, {invalid_header, crit, illegal_parameter_name}});
                    false ->
                        X
                end;
            (_) ->
                throw({error, {invalid_header, crit, invalid_format}})
        end,
    Header#{crit => lists:map(F, Value)};
parse_header_parameter_name(<<"crit">>, _Value, _Header) ->
    throw({error, {invalid_header, crit, invalid_format}});
parse_header_parameter_name(<<"b64">>, Value, Header) when is_boolean(Value) ->
    Header#{b64 => Value};
parse_header_parameter_name(<<"b64">>, _Value, _Header) ->
    throw({error, {invalid_header, b64, invalid_format}});
parse_header_parameter_name(Key, Value, Header) ->
    Header#{Key => Value}.

-spec parse_x5c_header_parameter_name([binary()], [jose:certificate()]) ->
          [jose:certificate()].
parse_x5c_header_parameter_name([], Acc) ->
    lists:reverse(Acc);
parse_x5c_header_parameter_name([H | T], Acc) when is_binary(H) ->
    case jose_base64:decode(H) of
        {ok, Data} ->
            Cert = try
                       public_key:pkix_decode_cert(Data, otp)
                   catch
                       error:Reason ->
                           throw({error, {invalid_header, x5c, Reason}})
                   end,
            parse_x5c_header_parameter_name(T, [Cert | Acc]);
        {error, Reason} ->
            throw({error, {invalid_header, x5c, Reason}})
    end;
parse_x5c_header_parameter_name(_Value, _Acc) ->
    throw({error, {invalid_header, x5c, invalid_format}}).

-spec decode_payload(header(), binary()) -> binary().
decode_payload(#{b64 := false} = Header, Data) ->
    Crit = maps:get(crit, Header, []),
    case lists:member(<<"b64">>, Crit) of
        true -> Data;
        false -> throw({error, {invalid_payload, malformatted_payload}})
    end;
decode_payload(Header, Data) ->
    Crit = maps:get(crit, Header, []),
    case lists:member(<<"b64">>, Crit) of
        true ->
            throw({error, {invalid_payload, malformatted_payload}});
        false ->
            case jose_base64:decodeurl(Data, #{padding => false}) of
                {ok, Payload} -> Payload;
                {error, Reason} -> throw({error, {invalid_payload, Reason}})
            end
    end.

-spec decode_signature(binary()) -> binary().
decode_signature(Data) ->
    case jose_base64:decodeurl(Data, #{padding => false}) of
        {ok, Signature} ->
            Signature;
        {error, Reason} ->
            throw({error, {invalid_signature, Reason}})
    end.

-spec collect_potential_verify_keys(atom(), term(), [jose_jwa:verify_key()], jose_jwa:alg()) -> [jose_jwa:verify_key()].
collect_potential_verify_keys(x5t, Fingerprint, Acc, Alg) when Alg =:= rs256;
                                                               Alg =:= rs384;
                                                               Alg =:= rs512 ->
    case jose_certificate_store:find(certificate_store_default, {sha1, Fingerprint}) of
        {ok, Cert} ->
            case jose_crypto:extract_pub_from_cert(Cert) of
                {'RSAPublicKey', _, _} = Key -> [Key | Acc];
                _Else -> Acc
            end;
        error ->
            Acc
    end;
collect_potential_verify_keys(x5t, Fingerprint, Acc, Alg) when Alg =:= es256;
                                                               Alg =:= es384;
                                                               Alg =:= es512 ->
    case jose_certificate_store:find(certificate_store_default, {sha1, Fingerprint}) of
        {ok, Cert} ->
            case jose_crypto:extract_pub_from_cert(Cert) of
                {{'ECPoint', _}, _} = PubKey -> [PubKey | Acc];
                _Else -> Acc
            end;
        error ->
            Acc
    end;
collect_potential_verify_keys('x5t#S256', Fingerprint, Acc, Alg) when Alg =:= rs256;
                                                                      Alg =:= rs384;
                                                                      Alg =:= rs512 ->
    case jose_certificate_store:find(certificate_store_default, {sha2, Fingerprint}) of
        {ok, Cert} ->
            case jose_crypto:extract_pub_from_cert(Cert) of
                {'RSAPublicKey', _, _} = PubKey -> [PubKey | Acc];
                _Else -> Acc
            end;
        error ->
            Acc
    end;
collect_potential_verify_keys('x5t#S256', Fingerprint, Acc, Alg) when Alg =:= es256;
                                                                      Alg =:= es384;
                                                                      Alg =:= es512 ->
    case jose_certificate_store:find(certificate_store_default, {sha2, Fingerprint}) of
        {ok, Cert} ->
            case jose_crypto:extract_pub_from_cert(Cert) of
                {{'ECPoint', _}, _} = PubKey -> [PubKey | Acc];
                _Else -> Acc
            end;
        error ->
            Acc
    end;
collect_potential_verify_keys(x5c, [], Acc, _Alg) ->
    Acc;
collect_potential_verify_keys(x5c, Chain, Acc, Alg) when Alg =:= rs256;
                                                         Alg =:= rs384;
                                                         Alg =:= rs512 ->
    [Root | _] = Chain,
    case jose_certificate_store:find(certificate_store_default, Root) of
        {ok, _} ->
            case jose_crypto:extract_pub_from_chain(Chain) of
                {'RSAPublicKey', _, _} = PubKey -> [PubKey | Acc];
                _Else -> Acc
            end;
        error ->
            Acc
    end;
collect_potential_verify_keys(x5c, Chain, Acc, Alg) when Alg =:= es256;
                                                         Alg =:= es384;
                                                         Alg =:= es512 ->
    [Root | _] = Chain,
    case jose_certificate_store:find(certificate_store_default, Root) of
        {ok, _} ->
            case jose_crypto:extract_pub_from_chain(Chain) of
                {{'ECPoint', _}, _} = PubKey -> [PubKey | Acc];
                _Else -> Acc
            end;
        error ->
            Acc
    end;
collect_potential_verify_keys(kid, KId, Acc, Alg) when Alg =:= rs256;
                                                       Alg =:= rs384;
                                                       Alg =:= rs512 ->
    case jose_key_store:find(key_store_default, KId) of
        {ok, {'RSAPublicKey', _, _} = PubKey} ->
            [PubKey | Acc];
        error ->
            Acc
    end;
collect_potential_verify_keys(kid, KId, Acc, Alg) when Alg =:= es256;
                                                       Alg =:= es384;
                                                       Alg =:= es512 ->
    case jose_key_store:find(key_store_default, KId) of
        {ok, {{'ECPoint', _}, _} = PubKey} ->
            [PubKey | Acc];
        error ->
            Acc
    end;
collect_potential_verify_keys(_Key, _Value, Acc, _Alg) ->
    Acc.
