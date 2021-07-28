%% Copyright (c) 2020, 2021 Bryan Frimin <bryan@frimin.fr>.
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

-module(jose_jws).

-export([reserved_header_parameter_names/0, supported_crits/0,
         encode_compact/3, encode_compact/4,
         decode_compact/3, decode_compact/4]).

-export_type([header/0,
              payload/0,
              compact/0,
              jws/0,
              encode_options/0,
              decode_error_reason/0]).

-type header() :: #{alg => jose:alg(),
                    jku => uri:uri(),
                    jwk => jose:jwk(),
                    kid => jose:kid(),
                    x5u => uri:uri(),
                    x5c => [jose:certificate()],
                    x5t => jose:certificate_thumbprint(),
                    'x5t#S256' => jose:certificate_thumbprint(),
                    typ => jose:media_type(),
                    cty => jose:media_type(),
                    b64 => boolean(),
                    crit => [jose:header_parameter_name()]}.

-type payload() :: binary().
-type compact() :: binary().

-type jws() :: {header(), payload()}.

-type encode_options() :: map().
-type decode_options() :: map().

-type decode_error_reason() ::
        invalid_format
      | {invalid_header, Key :: term(), Reason :: term()}
      | {invalid_header, Reason :: term()}
      | {invalid_payload, Reason :: term()}
      | {invalid_signature, Reason :: term()}.

-spec reserved_header_parameter_names() ->
        [jose:header_parameter_name()].
reserved_header_parameter_names() ->
  [<<"alg">>, <<"jku">>, <<"jwk">>, <<"kid">>,
   <<"x5u">>, <<"x5c">>, <<"x5t">>, <<"x5t#S256">>,
   <<"typ">>, <<"cty">>, <<"crit">>].

-spec supported_crits() ->
        [binary()].
supported_crits() ->
  [<<"b64">>].

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
  Signature = b64url:encode(jose_jwa:sign(Message, Alg, Key), [nopad]),
  <<Message/binary, $., Signature/binary>>.

-spec serialize_header(header()) -> binary().
serialize_header(Header) ->
  Object = maps:fold(fun serialize_header_parameter_name/3, #{}, Header),
  Data = json:serialize(Object, #{return_binary => true}),
  b64url:encode(Data, [nopad]).

-spec serialize_header_parameter_name(json:key(), term(), map()) ->
        #{json:key() => json:value()}.
serialize_header_parameter_name(alg, Alg, Header) ->
  Header#{<<"alg">> => jose_jwa:encode_alg(Alg)};
serialize_header_parameter_name(jku, Value, Header) when is_binary(Value) ->
  Header#{<<"jku">> => Value};
serialize_header_parameter_name(jku, URI, Header) ->
  Value = uri:serialize(URI),
  Header#{<<"jku">> => Value};
serialize_header_parameter_name(jwk, JWK, Header) ->
  %% TODO: serialize JWK with jose_jwk:serialize(...)
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
          b64:encode(X);
        (X) ->
          b64:encode(public_key:pkix_encode('OTPCertificate', X, otp))
      end,
  Value = lists:map(F, CertChain),
  Header#{<<"x5c">> => Value};
serialize_header_parameter_name(x5t, Fingerprint, Header) ->
  Value = b64url:encode(Fingerprint),
  Header#{<<"x5t">> => Value};
serialize_header_parameter_name('x5t#S256', Fingerprint, Header) ->
  Value = b64url:encode(Fingerprint),
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
  b64url:encode(Payload, [nopad]).

-spec decode_compact(compact(),
                     jose_jwa:alg(),
                     [jose_jwa:verify_key()] | jose_jwa:verify_key()) ->
        {ok, jws()} | {error, decode_error_reason()}.
decode_compact(Token, Alg, Key) ->
  decode_compact(Token, Alg, Key, #{}).

-spec decode_compact(compact(),
                     jose_jwa:alg(),
                     [jose_jwa:verify_key()],
                     decode_options()) ->
        {ok, jws()} | {error, decode_error_reason()}.
decode_compact(Token, Alg, Key, Options) when not is_list(Key) ->
  decode_compact(Token, Alg, [Key], Options);
decode_compact(Token, Alg, Keys0, _Options) ->
  try
    {Header0, Payload0, Signature0} = parse_parts(Token),
    Header = decode_header(Header0),
    Payload = decode_payload(Header, Payload0),
    Signature = decode_signature(Signature0),
    ensure_alg_match(maps:get(alg, Header), Alg),
    %% Message = <<(jose_base64:encodeurl(Header0, #{padding => false})), $.,
    %%             (jose_base64:encodeurl(Payload0, #{padding => false}))>>,
    Message = <<Header0/binary, $., Payload0/binary>>,

    CollectKeys = fun (K, V, Acc) ->
                      collect_potential_verify_keys(K, V, Acc, Alg)
                  end,
    VerifySig = fun (Key) ->
                    jose_jwa:is_valid(Message, Signature, Alg, Key)
                end,
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
  case b64url:decode(Data0, [nopad]) of
    {ok, Data} ->
      parse_header_object(Data);
    {error, Reason} ->
      throw({error, {invalid_header, Reason}})
  end.

-spec parse_header_object(binary()) -> header().
parse_header_object(Data) ->
  case json:parse(Data, #{duplicate_key_handling => error}) of
    {ok, Header} when is_map(Header) ->
      parse_header_parameter_names(Header);
    {ok, _} ->
      throw({error, {invalid_header, invalid_format}});
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
  case b64url:decode(Value) of
    {ok, Thumbprint} when byte_size(Thumbprint) =:= 20 ->
      Header#{x5t => Thumbprint};
    {ok, _} ->
      throw({error, {invalid_header, x5t, invalid_format}});
    {error, Reason} ->
      throw({error, {invalid_header, x5t, Reason}})
  end;
parse_header_parameter_name(<<"x5t">>, _Value, _Header) ->
  throw({error, {invalid_header, x5t, invalid_format}});
parse_header_parameter_name(<<"x5t#S256">>, Value, Header) when is_binary(Value) ->
  case b64url:decode(Value) of
    {ok, Thumbprint} when byte_size(Thumbprint) =:= 32 ->
      Header#{'x5t#S256' => Thumbprint};
    {ok, _} ->
      throw({error, {invalid_header, 'x5t#S256', invalid_format}});
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
              case lists:member(X, supported_crits()) of
                true ->
                  X;
                false ->
                  throw({error, {invalid_header, crit, unsupported}})
              end
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
  case b64:decode(H) of
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
decode_payload(Header, Data) ->
  case maps:get(b64, Header, true) of
    false -> Data;
    true ->
      case b64url:decode(Data, [nopad]) of
        {ok, Payload} -> Payload;
        {error, Reason} -> throw({error, {invalid_payload, Reason}})
      end
  end.

-spec decode_signature(binary()) -> binary().
decode_signature(Data) ->
  case b64url:decode(Data, [nopad]) of
    {ok, Signature} ->
      Signature;
    {error, Reason} ->
      throw({error, {invalid_signature, Reason}})
  end.

-spec ensure_alg_match(jose_jwa:alg(), jose_jwa:alg()) -> ok.
ensure_alg_match(TokenAlg, Alg) ->
  if TokenAlg =:= Alg -> ok;
     true -> throw({error, alg_mismatch})
  end.

-spec collect_potential_verify_keys(atom(), term(), [jose_jwa:verify_key()], jose_jwa:alg()) -> [jose_jwa:verify_key()].
collect_potential_verify_keys(x5t, Fingerprint, Acc, Alg) when Alg =:= rs256;
                                                               Alg =:= rs384;
                                                               Alg =:= rs512 ->
  case jose_certificate_store:find(certificate_store_default, {sha1, Fingerprint}) of
    {ok, Cert} ->
      case jose_pkix:get_cert_pubkey(Cert) of
        {'RSAPublicKey', _, _} = Key -> [Key | Acc];
        _Else -> Acc
      end;
    error ->
      Acc
  end;
collect_potential_verify_keys(x5t, Fingerprint, Acc, Alg) when Alg =:= es256;
                                                               Alg =:= es384;
                                                               Alg =:= es521 ->
  case jose_certificate_store:find(certificate_store_default, {sha1, Fingerprint}) of
    {ok, Cert} ->
      case jose_pkix:get_cert_pubkey(Cert) of
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
      case jose_pkix:get_cert_pubkey(Cert) of
        {'RSAPublicKey', _, _} = PubKey -> [PubKey | Acc];
        _Else -> Acc
      end;
    error ->
      Acc
  end;
collect_potential_verify_keys('x5t#S256', Fingerprint, Acc, Alg) when Alg =:= es256;
                                                                      Alg =:= es384;
                                                                      Alg =:= es521 ->
  case jose_certificate_store:find(certificate_store_default, {sha2, Fingerprint}) of
    {ok, Cert} ->
      case jose_pkix:get_cert_pubkey(Cert) of
        {{'ECPoint', _}, _} = PubKey -> [PubKey | Acc];
        _Else -> Acc
      end;
    error ->
      Acc
  end;
collect_potential_verify_keys(x5c, [], Acc, _) ->
  Acc;
collect_potential_verify_keys(x5c, Chain, Acc, Alg) when Alg =:= rs256;
                                                         Alg =:= rs384;
                                                         Alg =:= rs512 ->
  [Root | _] = Chain,
  case jose_certificate_store:find(certificate_store_default, Root) of
    {ok, _} ->
      case jose_pkix:get_cert_chain_pubkey(Chain) of
        {ok, PubKey} -> [PubKey | Acc];
        {error, _} -> Acc
      end;
    error ->
      Acc
  end;
collect_potential_verify_keys(x5c, Chain, Acc, Alg) when Alg =:= es256;
                                                         Alg =:= es384;
                                                         Alg =:= es521 ->
  [Root | _] = Chain,
  case jose_certificate_store:find(certificate_store_default, Root) of
    {ok, _} ->
      case jose_pkix:get_cert_chain_pubkey(Chain) of
        {ok, PubKey} -> [PubKey | Acc];
        {error, _} -> Acc
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
                                                       Alg =:= es521 ->
  case jose_key_store:find(key_store_default, KId) of
    {ok, {{'ECPoint', _}, _} = PubKey} ->
      [PubKey | Acc];
    error ->
      Acc
  end;
collect_potential_verify_keys(_Key, _Value, Acc, _) ->
  Acc.
