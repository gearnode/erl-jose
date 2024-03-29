%% Copyright (c) 2020, 2021 Exograd SAS.
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

-module(jose_jws_decoder).

-export([decode_compact/3]).

-export_type([options/0, error/0, error_reason/0]).

-type options() ::
        #{trusted_remotes =>
            #{cacertfile => file:filename_all(),
              certificates => [jose:certificate_thumbprint()],
              public_keys => [jose:certificate_thumbprint()]},
          certificate_store => et_gen_server:ref(),
          key_store => et_gen_server:ref(),
          key => term()}.


-type state() :: #{jws => map(), key => term(), cert => term()}.

-type error() ::
        #{key => atom(),
          part => header | body | signature,
          reason := error_reason()}.

-type error_reason() ::
        {invalid_format, Value :: term()}
      | invalid_encoding
      | missing
      | jose_jwk:decode_error()
      | untrusted_certificate
      | jose_x5u:decode_error_reason()
      | jose_x5c:decode_error_reason()
      | jose_x5t:decode_error_reason()
      | jose_x5tS256:decode_error_reason()
      %% | jose_media_type:decode_error_reason()
      | not_allowed_parameter_name
      | unsupported_parameter_name
      | mismatch_algorithm
      | certificate_missmatch
      | pubkey_missmatch
      | untrusted_certificate.

-type header_step() ::
        alg
      | jku
      | jwk
      | kid
      | x5u
      | x5c
      | x5t
      | 'x5t#S256'
      | typ
      | cty
      | crit
      | b64
      | extra_data.

-spec decode_compact(binary(), jose:alg(), options()) ->
        {ok, jose:jws()} | {error, error()}.
decode_compact(Bin, Algorithm, Options) ->
  try
    {P1, P2, P3} = split(Bin),
    Header = decode_header(P1, Options),
    is_algorithm_match(Header, Algorithm) orelse
      throw({error, #{part => header, reason => mismatch_algorithm}}),

    Body = decode_body(Header, P2),
    _Signature = decode_signature(P3),
    {Header, Body}
  catch
    throw:{error, Reason} ->
      {error, Reason}
  end.

-spec split(binary()) -> {binary(), binary(), binary()}.
split(Bin) ->
  case binary:split(Bin, <<$.>>, [global]) of
    [Header, Body, Signature] ->
      {Header, Body, Signature};
    Value ->
      throw({error, #{reason => {invalid_format, Value}}})
  end.

-spec decode_header(binary(), options()) -> jose_jws:header().
decode_header(Bin, Options) ->
  case b64url:decode(Bin, [nopad]) of
    {ok, DecodedBin} ->
      case json:parse(DecodedBin, #{duplicate_key_handling => error}) of
        {ok, Data} when is_map(Data) ->
          State = maps:with([key], Options),
          decode_header(alg, Data, Options, State);
        {ok, Value} ->
          throw({error,
                 #{part => header, reason => {invalid_format, Value}}});
        {error, Reason} ->
          throw({error, #{part => header, reason => Reason}})
      end;
    {error, _} ->
      throw({error,
             #{part => header, reason => invalid_encoding}})
  end.

-spec decode_header(header_step(), map(), options(), state()) ->
        jose_jws:header().
%% https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.1
decode_header(alg, Data, Options, State) ->
  JWS =
    case maps:find(<<"alg">>, Data) of
      error ->
        throw({error,
               #{key => alg, part => header, reason => missing}});
      {ok, Value} when is_binary(Value) ->
        case jose_jwa:decode_alg(Value) of
          {ok, Algorithm} ->
            #{alg => Algorithm};
          {error, Reason} ->
            throw({error,
                   #{key => alg, part => header, reason => Reason}})
        end;
      {ok, Value} ->
        throw({error,
               #{key => alg, part => header,
                 reason => {invalid_format, Value}}})
    end,
  decode_header(kid, Data, Options, State#{jws => JWS});

%% https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4
decode_header(kid, Data, Options, #{jws := JWS} = State) ->
  State1 =
    case maps:find(<<"kid">>, Data) of
      error ->
        State;
      {ok, Value} when is_binary(Value) ->
        State#{jws => JWS#{kid => Value}};
      {ok, Value} ->
        throw({error,
               #{key => kid, part => header,
                 reason => {invalid_format, Value}}})
    end,
  decode_header(jku, Data, Options, State1);

%% https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.2
decode_header(jku, Data, Options, #{jws := JWS} = State) ->
  State1 =
    case maps:find(<<"jku">>, Data) of
      error ->
        State;
      {ok, Value} when is_binary(Value) ->
        State#{jws => JWS#{jku => Value}};
      {ok, Value} ->
        throw({error,
               #{key => jku, part => header,
                 reason => {invalid_format, Value}}})
    end,
  decode_header(jwk, Data, Options, State1);

%% https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.3
decode_header(jwk, Data, Options, #{jws := JWS} = State) ->
  State1 =
    case maps:find(<<"jwk">>, Data) of
      error ->
        State;
      {ok, Value} when is_binary(Value) ->
        case jose_jwk:decode(Value, Options) of
          {ok, JWK} ->
            Key = jose_jwk:to_record(JWK),
            is_key_trustable(Key, Options) orelse
              throw({error, #{key => jwk, part => header,
                              reason => untrusted_public_key}}),
            case maps:find(key, State) of
              {ok, Key} ->
                State#{jws => JWS#{jwk => JWK}};
              {ok, _} ->
                throw({error, #{key => jwk, part => header,
                                reason => pubkey_missmatch}});
              error ->
                State#{jws => JWS#{jwk => JWK},
                       key => jose_jwk:to_record(JWK)}
            end;
          {error, Reason} ->
            throw({error,
                   #{key => jwk, part => header, reason => Reason}})
        end;
      {ok, Value} ->
        throw({error,
               #{key => jwk, part => header,
                 reason => {invalid_format, Value}}})
    end,
  decode_header(x5u, Data, Options, State1);

%% https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.5
decode_header(x5u, Data, Options, #{jws := JWS} = State) ->
  State1 =
    case maps:find(<<"x5u">>, Data) of
      error ->
        State;
      {ok, Value} ->
        TrustedRemotes = maps:get(trusted_remotes, Options, #{}),
        case jose_x5u:decode(Value, TrustedRemotes) of
          {ok, []} ->
            State;
          {ok, Chain} ->
            is_certificate_chain_trustable(Chain, TrustedRemotes) orelse
              throw({error,
                     #{key => x5u, part => header,
                       reason => untrusted_certificate}}),
            Certificate = lists:last(Chain),
            PubKey = jose_pkix:get_cert_pubkey(Certificate),
            case maps:get(key, State) of
              {ok, PubKey} ->
                State#{jws => JWS#{x5u => Value}, cert => Certificate};
              {ok, _} ->
                throw({error, #{key => x5u, part => header,
                                reason => pubkey_missmatch}});
              error ->
                State#{jws => JWS#{x5u => Value}, cert => Certificate}
            end;
          {error, Reason} ->
            throw({error,
                   #{key => x5u, part => header, reason => Reason}})
        end
    end,
  decode_header(x5c, Data, Options, State1);

%% https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6
decode_header(x5c, Data, Options, #{jws := JWS} = State) ->
  State1 =
    case maps:find(<<"x5c">>, Data) of
      error ->
        State;
      {ok, Value} ->
        case jose_x5c:decode(Value) of
          {ok, []} ->
            State;
          {ok, Chain} ->
            is_certificate_chain_trustable(Chain, Options) orelse
              throw({error,
                     #{key => x5c, part => header,
                       reason => untrusted_certificate}}),
            Certificate = lists:last(Chain),
            case maps:find(cert, State) of
              {ok, Certificate} ->
                PubKey = jose_pkix:get_cert_pubkey(Certificate),
                case maps:find(key, State) of
                  {ok, PubKey} ->
                    State#{jws => JWS#{x5c => Chain}};
                  {ok, _} ->
                    throw({error, #{key => x5c, part => header,
                                    reason => pubkey_missmatch}});
                  error ->
                    State#{jws => JWS#{x5c => Chain}}
                end;
              {ok, _} ->
                throw({error, #{key => x5c, part => header,
                                reason => certificate_missmatch}});
              error ->
                State#{jws => JWS#{x5c => Chain}, cert => Certificate}
            end;
          {error, Reason} ->
            throw({error,
                   #{key => x5c, part => header, reason => Reason}})
        end
    end,
  decode_header(x5t, Data, Options, State1);

%% https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.7
decode_header(x5t, Data, Options, #{jws := JWS} = State) ->
  State1 =
    case maps:find(<<"x5t">>, Data) of
      error ->
        State;
      {ok, Value} ->
        case jose_x5t:decode(Value) of
          {ok, Thumbprint} ->
            case maps:find(cert, State) of
              {ok, Certificate} ->
                jose_pkix:cert_thumbprint(Certificate) =:= Thumbprint orelse
                  throw({error, #{key => x5t, part => header,
                                  reason => certificate_missmatch}}),
                State#{jws => JWS#{x5t => Thumbprint}};
              error ->
                State#{jws => JWS#{x5t => Thumbprint}}
            end;
          {error, Reason} ->
            throw({error,
                   #{key => x5t, part => header, reason => Reason}})
        end
    end,
  decode_header('x5t#S256', Data, Options, State1);

%% https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.8
decode_header('x5t#S256', Data, Options, #{jws := JWS} = State) ->
  State1 =
    case maps:find(<<"x5t#S256">>, Data) of
      error ->
        State;
      {ok, Value} ->
        case jose_x5tS256:decode(Value) of
          {ok, Thumbprint} ->
            case maps:find(cert, State) of
              {ok, Certificate} ->
                jose_pkix:cert_thumbprint(Certificate) =:= Thumbprint orelse
                  throw({error, #{key => 'x5t#S256', part => header,
                                  reason => certificate_missmatch}}),
                State#{jws => JWS#{'x5t#S256' => Thumbprint}};
              error ->
                State#{jws => JWS#{'x5t#S256' => Thumbprint}}
            end;
          {error, Reason} ->
            throw({error,
                   #{key => 'x5t#S256', part => header, reason => Reason}})
        end
    end,
  decode_header(typ, Data, Options, State1);

%% https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.9
decode_header(typ, Data, Options, #{jws := JWS} = State) ->
  State1 =
    case maps:find(<<"typ">>, Data) of
      error ->
        State;
      {ok, Value} when is_binary(Value) ->
        case jose_media_type:parse(Value) of
          {ok, MT} ->
            State#{jws => JWS#{typ => MT}};
          {error, Reason} ->
            throw({error,
                   #{key => typ, part => header, reason => Reason}})
        end;
      {ok, Value} ->
        throw({error,
               #{key => typ, part => header,
                 reason => {invalid_format, Value}}})
    end,
  decode_header(cty, Data, Options, State1);

%% https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.10
decode_header(cty, Data, Options, #{jws := JWS} = State) ->
  State1 =
    case maps:find(<<"cty">>, Data) of
      error ->
        State;
      {ok, Value} when is_binary(Value) ->
        case jose_media_type:parse(Value) of
          {ok, MT} ->
            State#{jws => JWS#{cty => MT}};
          {error, Reason} ->
            throw({error,
                   #{key => cty, part => header, reason => Reason}})
        end;
      {ok, Value} ->
        throw({error,
               #{key => cty, part => header,
                 reason => {invalid_format, Value}}})
    end,
  decode_header(crit, Data, Options, State1);

%% https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11
decode_header(crit, Data, Options, #{jws := JWS} = State) ->
  ReservedParameterNames = jose_jws:reserved_header_parameter_names() ++
    jose_jwa:reserved_header_parameter_names(),
  F =
    fun
      (ParameterName) when is_binary(ParameterName) ->
        case lists:member(ParameterName, ReservedParameterNames) of
          true ->
            throw({error, #{key => crit, part => header,
                            reason => {unallowed, ParameterName}}});
          false ->
            case lists:member(ParameterName, jose_jws:supported_crits()) of
              true ->
                ParameterName;
              false ->
                throw({error, #{key => crit, part => header,
                                reason => {unsupported, ParameterName}}})
            end
        end;
      (Value) ->
        throw({error, #{key => crit, part => header,
                        reason => {invalid_format, Value}}})
    end,
  State1 =
    case maps:find(<<"crit">>, Data) of
      error ->
        State;
      {ok, Values} when is_list(Values) ->
        State#{jws => JWS#{crit => lists:map(F, Values)}};
      {ok, Value} ->
        throw({error,
               #{key => crit, part => header,
                 reason => {invalid_format, Value}}})
    end,
  decode_header(b64, Data, Options, State1);

%% https://datatracker.ietf.org/doc/html/rfc7797#section-3
decode_header(b64, Data, Options, #{jws := JWS} = State) ->
  State1 =
    case maps:find(<<"b64">>, Data) of
      error ->
        State;
      {ok, Value} when is_boolean(Value) ->
        State#{jws => JWS#{b64 => Value}};
      {ok, Value} ->
        throw({error, #{key => b64, part => header,
                        reason => {invalid_format, Value}}})
    end,
  decode_header(extra_data, Data, Options, State1);

decode_header(extra_data, Data, _, #{jws := JWS} = State) ->
  Keys = lists:map(fun atom_to_binary/1, maps:keys(JWS)),
  ExtraData = maps:without(Keys, Data),
  State#{jws => maps:merge(JWS, ExtraData)}.

-spec decode_body(jose_jws:header(), binary()) -> binary().
decode_body(Header, Bin) ->
  case maps:get(b64, Header, true) of
    false ->
      Bin;
    true ->
      case b64url:decode(Bin, [nopad]) of
        {ok, Body} ->
          Body;
        {error, Reason} ->
          throw({error, #{part => body, reason => Reason}})
      end
  end.

-spec decode_signature(binary()) -> binary().
decode_signature(Bin) ->
  case b64url:decode(Bin, [nopad]) of
    {ok, Signature} ->
      Signature;
    {error, Reason} ->
      throw({error, #{part => signature, reason => Reason}})
  end.

-spec is_certificate_chain_trustable(jose:certificate_chain(), options()) ->
        boolean().
is_certificate_chain_trustable([Root | _], Options) ->
  Store = maps:get(certificate_store, Options, certificate_store_default),
  case jose_certificate_store:find(Store, Root) of
    {ok, _} ->
      true;
    error ->
      false
  end.

-spec is_algorithm_match(jose_jws:header(), jose:alg()) -> boolean().
is_algorithm_match(Header, Algorithm) ->
  maps:get(alg, Header) =:= Algorithm.

-spec is_key_trustable(jose:jwk(), options()) -> boolean().
is_key_trustable(Key, Options) ->
  PubKey = jose_pkix:privkey_to_pubkey(Key),
  Store = maps:get(key_store, Options, key_store_default),
  case jose_key_store:find(Store, PubKey) of
    {ok, _} ->
      true;
    error ->
      false
  end.
