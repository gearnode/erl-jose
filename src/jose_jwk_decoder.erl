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

-module(jose_jwk_decoder).

-export([decode/2]).

-export_type([options/0,
              error/0, error_reason/0]).

-type error() :: #{key => atom(),
                   reason := error_reason()}.

-type error_reason() ::
        missing
      | empty
      | {unsupported, Value :: term()}
      | {invalid_format, Value :: term()}
      | jose_jwa:decode_alg_error_reason()
      | untrusted_certificate
      | certificate_missmatch 
      | jose_x5u:decode_error_reason()
      | jose_x5c:decode_error_reason()
      | jose_x5t:decode_error_reason()
      | jose_x5tS256:decode_error_reason()
      | b64url:decode_error_reason()
      | #{key => oth, reason => error_reason()}.

-type options() ::
        #{trusted_remotes =>
            #{cacertfile => file:filename_all(),
              certificates => [jose:certificate_thumbprint()],
              public_keys => [jose:certificate_thumbprint()]},
         certificate_store => et_gen_server:ref()}.

-type step() ::
        kty
      | use
      | key_ops
      | alg
      | kid
      | x5u
      | x5c
      | x5t
      | 'x5t#S256'
      | key_data
      | validate.

-type state() :: #{jwk => map(), cert => jose:certificate()}.

-spec decode(binary() | map(), options()) ->
        {ok, jose:jwk()} | {error, error()}.
decode(Bin, Options) when is_binary(Bin) ->
  case json:parse(Bin, #{duplicate_key_handling => error}) of
    {ok, Data} when is_map(Data) ->
      decode(Data, Options);
    {ok, _} ->
      {error, #{reason => invalid_format}};
    {error, Reason} ->
      {error, #{reason => Reason}}
  end;
decode(Data, Options) when is_map(Data) ->
  try
    {ok, decode(kty, Data, Options, #{})}
  catch
    throw:{error, Reason} ->
      {error, Reason}
  end;
decode(_, _) ->
  {error, #{reason => invalid_format}}.

-spec decode(step(), map(), options(), state()) -> jose:jwk().
%% https://tools.ietf.org/html/rfc7517#section-4.1
decode(kty, Data, Options, State) ->
  Kty =
    case maps:find(<<"kty">>, Data) of
      error ->
        throw({error, #{key => kty, reason => missing}});
      {ok, <<"oct">>} ->
        oct;
      {ok, <<"RSA">>} ->
        'RSA';
      {ok, <<"EC">>} ->
        'EC';
      {ok, Value} ->
        throw({error, #{key => kty, reason => {unsupported, Value}}})
    end,
  decode(use, Data, Options, State#{jwk => #{kty => Kty}});

%% https://tools.ietf.org/html/rfc7517#section-4.2
decode(use, Data, Options, #{jwk := JWK} = State) ->
  JWK1 =
    case maps:find(<<"use">>, Data) of
      error ->
        JWK;
      {ok, <<"sig">>} ->
        JWK#{use => sig};
      {ok, <<"enc">>} ->
        JWK#{use => enc};
      {ok, Value} when is_binary(Value) ->
        throw({error, #{key => use, reason => {unsupported, Value}}});
      {ok, Value} ->
        throw({error, #{key => use, reason => {invalid_format, Value}}})
    end,
  decode(key_ops, Data, Options, State#{jwk => JWK1});

%% https://tools.ietf.org/html/rfc7517#section-4.3
decode(key_ops, Data, Options, #{jwk := JWK} = State) ->
  F = fun
        (<<"sign">>) -> sign;
        (<<"verify">>) -> verify;
        (<<"encrypt">>) -> encrypt;
        (<<"decrypt">>) -> decrypt;
        (<<"wrapKey">>) -> wrapKey;
        (<<"unwrapKey">>) -> unwrapKey;
        (<<"deriveKey">>) -> deriveKey;
        (<<"deriveBits">>) -> deriveBits;
        (Value) when is_binary(Value) ->
          throw({error, #{key => key_ops, reason => {unsupported, Value}}});
        (Value) ->
          throw({error, #{key => key_ops, reason => {invalid_format, Value}}})
      end,
  JWK1 =
    case maps:find(<<"key_ops">>, Data) of
      error ->
        JWK;
      {ok, Value} when is_list(Value) ->
        Operations = lists:map(F, Value),
        JWK#{key_ops => Operations};
      {ok, Value} ->
        throw({errot, #{key => key_ops, reason => {invalid_format, Value}}})
    end,
  decode(alg, Data, Options, State#{jwk => JWK1});

%% https://tools.ietf.org/html/rfc7517#section-4.4
decode(alg, Data, Options, #{jwk := JWK} = State) ->
  JWK1 =
    case maps:find(<<"alg">>, Data) of
      error ->
        JWK;
      {ok, Value} when is_binary(Value) ->
        case jose_jwa:decode_alg(Value) of
          {ok, Alg} ->
            JWK#{alg => Alg};
          {error, Reason} ->
            throw({error, #{key => alg, reason => Reason}})
        end;
      {ok, Value} ->
        throw({error, #{key => alg, reason => {invalid_format, Value}}})
    end,
  decode(kid, Data, Options, State#{jwk => JWK1});

%% https://tools.ietf.org/html/rfc7517#section-4.5
decode(kid, Data, Options, #{jwk := JWK} = State) ->
  JWK1 =
    case maps:find(<<"kid">>, Data) of
      error ->
        JWK;
      {ok, Kid} when is_binary(Kid) ->
        JWK#{kid => Kid};
      {ok, Value} ->
        throw({error, #{key => kid, reason => {invalid_format, Value}}})
    end,
  decode(x5u, Data, Options, State#{jwk => JWK1});

%% https://tools.ietf.org/html/rfc7517#section-4.6
decode(x5u, Data, Options, #{jwk := JWK} = State) ->
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
            is_certificate_chain_trustable(Chain, Options) orelse
              throw({error, #{key => x5u, reason => untrusted_certificate}}),
            Certificate = lists:last(Chain),
            State#{jwk => JWK#{x5u => Value}, cert => Certificate};
          {error, Reason} ->
            throw({error, #{key => x5u, reason => Reason}})
        end
    end,
  decode(x5c, Data, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.7
decode(x5c, Data, Options, #{jwk := JWK} = State) ->
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
              throw({error, #{key => x5c, reason => untrusted_certificate}}),
            Certificate = lists:last(Chain),
            case maps:find(cert, State) of
              {ok, Certificate} ->
                State#{jwk => JWK#{x5c => Chain}};
              {ok, _} ->
                throw({error, #{key => x5c, reason => certificate_missmatch}});
              error ->
                State#{jwk => JWK#{x5c => Chain}, cert => Certificate}
            end;
          {error, Reason} ->
            throw({error, #{key => x5c, reason => Reason}})
        end
    end,
  decode(x5t, Data, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.8
decode(x5t, Data, Options, #{jwk := JWK} = State) ->
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
                  throw({error, #{key => x5t,
                                  reason => certificate_missmatch}}),
                State#{jwk => JWK#{x5t => Thumbprint}};
              error ->
                State#{jwk => JWK#{x5t => Thumbprint}}
            end;
          {error, Reason} ->
            throw({error, #{key => x5t, reason => Reason}})
        end
    end,
  decode('x5t#S256', Data, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.9
decode('x5t#S256', Data, Options, #{jwk := JWK} = State) ->
  State1 =
    case maps:find(<<"x5t#S256">>, Data) of
      error ->
        State;
      {ok, Value} ->
        case jose_x5tS256:decode(Value) of
          {ok, Thumbprint} ->
            case maps:find(cert, State) of
              {ok, Certificate} ->
                jose_pkix:cert_thumbprint256(Certificate) =:= Thumbprint orelse
                  throw({error, #{key => 'x5t#S256',
                                  reason => certificate_missmatch}}),
                State#{jwk => JWK#{'x5t#S256' => Thumbprint}};
              error ->
                State#{jwk => JWK#{'x5t#S256' => Thumbprint}}
            end;
          {error, Reason} ->
            throw({error, #{key => 'x5t#S256', reason => Reason}})
        end
    end,
  decode(key_data, Data, Options, State1);

decode(key_data, Data, Options, #{jwk := JWK} = State) ->
  JWK1 =
    case maps:get(kty, JWK) of
      oct ->
        decode_oct(Data, JWK);
      'RSA' ->
        decode_rsa(Data, JWK);
      'EC' ->
        decode_ec(Data, JWK)
    end,
  decode(validate, Data, Options, State#{jwk => JWK1});

decode(validate, _, _, #{jwk := #{kty := oct}, cert := _}) ->
  throw({error, #{reason => certificate_missmatch}});
decode(validate, _, _, #{jwk := JWK, cert := Cert}) ->
  KeyPub = jose_pkix:privkey_to_pubkey(jose_jwk:to_record(JWK)),
  CertPub = jose_pkix:get_cert_pubkey(Cert),
  case KeyPub =:= CertPub of
    true ->
      JWK;
    false ->
      throw({error, #{reason => certificate_missmatch}})
  end;
decode(validate, _, _, #{jwk := JWK}) ->
  JWK.

%% https://tools.ietf.org/html/rfc7518#section-6.2
-spec decode_ec(map(), map()) -> jose_jwk:ec().
decode_ec(Data, State) ->
  decode_ec(crv, Data, State).

%% https://tools.ietf.org/html/rfc7518#section-6.2.1.1
decode_ec(crv, Data, State) ->
  State1 =
    case maps:find(<<"crv">>, Data) of
      error ->
        throw({error, #{key => crv, reason => missing}});
      {ok, <<"P-256">>} ->
        State#{crv => 'P-256'};
      {ok, <<"P-384">>} ->
        State#{crv => 'P-384'};
      {ok, <<"P-521">>} ->
        State#{crv => 'P-521'};
      {ok, Value} when is_binary(Value) ->
        throw({error, #{key => crv, reason => {unsupported, Value}}});
      {ok, Value} ->
        throw({error, #{key => crv, reason => {invalid_format, Value}}})
    end,
  decode_ec(x, Data, State1);

%% https://tools.ietf.org/html/rfc7518#section-6.2.1.2
decode_ec(x, Data, #{crv := Crv} = State) ->
  State1 =
    case maps:find(<<"x">>, Data) of
      error ->
        throw({error, #{key => x, reason => missing}});
      {ok, Value} when is_binary(Value) ->
        case b64url:decode(Value, [nopad]) of
          {error, Reason} ->
            throw({error, #{key => x, reason => Reason}});
          {ok, X} when Crv =:= 'P-256', byte_size(X) =:= 32;
                       Crv =:= 'P-384', byte_size(X) =:= 48;
                       Crv =:= 'P-521', byte_size(X) =:= 66 ->
            State#{x => X};
          {ok, DV} ->
            throw({error, #{key => x, reason => {unsupported, DV}}})
        end;
      {ok, Value} ->
        throw({error, #{key => x, reason => {invalid_format, Value}}})
    end,
  decode_ec(y, Data, State1);

%% https://tools.ietf.org/html/rfc7518#section-6.2.1.3
decode_ec(y, Data, #{crv := Crv} = State) ->
  State1 =
    case maps:find(<<"y">>, Data) of
      %% XXX: not all Elliptic Curve required the "y" paramater.
      error ->
        throw({error, #{key => y, reason => missing}});
      {ok, Value} when is_binary(Value) ->
        case b64url:decode(Value, [nopad]) of
          {error, Reason} ->
            throw({error, #{key => y, reason => Reason}});
          {ok, Y} when Crv =:= 'P-256', byte_size(Y) =:= 32;
                       Crv =:= 'P-384', byte_size(Y) =:= 48;
                       Crv =:= 'P-521', byte_size(Y) =:= 66 ->
            State#{y => Y};
          {ok, DV} ->
            throw({error, #{key => y, reason => {unsupported, DV}}})
        end;
      {ok, Value} ->
        throw({error, #{key => y, reason => {invalid_format, Value}}})
    end,
  decode_ec(d, Data, State1);

%% https://tools.ietf.org/html/rfc7518#section-6.2.2
%% https://tools.ietf.org/html/rfc7518#section-6.2.2.1
decode_ec(d, Data, State) ->
  case maps:find(<<"d">>, Data) of
    error ->
      State;
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {error, Reason} ->
          throw({error, #{key => d, reason => Reason}});
        {ok, D} when is_binary(Value) ->
          %% TODO: check the size of the octect string.
          State#{d => D};
        {ok, DV} ->
          throw({error, #{key => d, reason => {invalid_format, DV}}})
      end;
    {ok, Value} ->
      throw({error, #{key => d, reason => {invalid_format, Value}}})
  end.

%% https://tools.ietf.org/html/rfc7518#section-6.3
-spec decode_rsa(map(), map()) -> jose_jwk:rsa().
decode_rsa(Data, State) ->
  decode_rsa(n, Data, State).

%% https://tools.ietf.org/html/rfc7518#section-6.3.1.1
decode_rsa(n, Data, State) ->
  case maps:find(<<"n">>, Data) of
    error ->
      throw({error, #{key => n, reason => missing}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, N} ->
          State1 = State#{n => bytes_integer(N)},
          decode_rsa(e, Data, State1);
        {error, Reason} ->
          throw({error, #{key => n, reason => Reason}})
      end;
    {ok, Value} ->
      throw({error, #{key => n, reason => {invalid_format, Value}}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.1.2
decode_rsa(e, Data, State) ->
  case maps:find(<<"e">>, Data) of
    error ->
      throw({error, #{key => e, reason => missing}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, E} ->
          State1 = State#{e => bytes_integer(E)},
          decode_rsa(d, Data, State1);
        {error, Reason} ->
          throw({error, #{key => e, reason => Reason}})
      end;
    {ok, Value} ->
      throw({error, #{key => e, reason => {invalid_format, Value}}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2
%% https://tools.ietf.org/html/rfc7518#section-6.3.2.1
decode_rsa(d, Data, State) ->
  case maps:find(<<"d">>, Data) of
    error ->
      State;
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, D} ->
          State1 = State#{d => bytes_integer(D)},
          decode_rsa(p, Data, State1);
        {error, Reason} ->
          throw({error, #{key => d, reason => Reason}})
      end;
    {ok, Value} ->
      throw({error, #{key => d, reason => {invalid_format, Value}}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.2
decode_rsa(p, Data, State) ->
  case maps:find(<<"p">>, Data) of
    error ->
      State;
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, P} ->
          State1 = State#{p => bytes_integer(P)},
          decode_rsa(q, Data, State1);
        {error, Reason} ->
          throw({error, #{key => p, reason => Reason}})
      end;
    {ok, Value} ->
      throw({error, #{key => p, reason => {invalid_format, Value}}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.3
decode_rsa(q, Data, State) ->
  case maps:find(<<"q">>, Data) of
    error ->
      throw({error, #{key => q, reason => missing}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, Q} ->
          State1 = State#{q => bytes_integer(Q)},
          decode_rsa(dp, Data, State1);
        {error, Reason} ->
          throw({error, #{key => q, reason => Reason}})
      end;
    {ok, Value} ->
      throw({error, #{key => q, reason => {invalid_format, Value}}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.4
decode_rsa(dp, Data, State) ->
  case maps:find(<<"dp">>, Data) of
    error ->
      throw({error, #{key => dp, reason => missing}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, DP} ->
          State1 = State#{dp => bytes_integer(DP)},
          decode_rsa(dq, Data, State1);
        {error, Reason} ->
          throw({error, #{key => dp, reason => Reason}})
      end;
    {ok, Value} ->
      throw({error, #{key => dp, reason => {invalid_format, Value}}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.5
decode_rsa(dq, Data, State) ->
  case maps:find(<<"dq">>, Data) of
    error ->
      throw({error, #{key => dq, reason => missing}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, DQ} ->
          State1 = State#{dq => bytes_integer(DQ)},
          decode_rsa(qi, Data, State1);
        {error, Reason} ->
          throw({error, #{key => dq, reason => Reason}})
      end;
    {ok, Value} ->
      throw({error, #{key => dq, reason => {invalid_format, Value}}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.6
decode_rsa(qi, Data, State) ->
  case maps:find(<<"qi">>, Data) of
    error ->
      throw({error, #{key => qi, reason => missing}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, QI} ->
          State1 = State#{qi => bytes_integer(QI)},
          decode_rsa(oth, Data, State1);
        {error, Reason} ->
          throw({error, #{key => qi, reason => Reason}})
      end;
    {ok, Value} ->
      throw({error, #{key => qi, reason => {invalid_format, Value}}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.7
decode_rsa(oth, Data, State) ->
  case maps:find(<<"oth">>, Data) of
    error ->
      State;
    {ok, []} ->
      throw({error, #{key => oth, reason => empty}});
    {ok, Value} when is_list(Value) ->
      F = fun (X) -> decode_rsa_oth(X, #{}) end,
      State#{oth => lists:map(F, Value)};
    {ok, Value} ->
      throw({error, #{key => oth, reason => {invalid_format, Value}}})
  end.

% https://tools.ietf.org/html/rfc7518#section-6.3.2.7.1
decode_rsa_oth(Data, State) ->
  decode_rsa_oth(r, Data, State).

decode_rsa_oth(r, Data, State) ->
  case maps:find(<<"r">>, Data) of
    error ->
      throw({error, #{key => oth, reason => #{key => r, reason => missing}}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, R} ->
          State1 = State#{r => bytes_integer(R)},
          decode_rsa_oth(d, Data, State1);
        {error, Reason} ->
          throw({error, #{key => oth, reason =>
                            #{key => r, reason => Reason}}})
      end;
    {ok, Value} ->
      throw({error, #{key => oth, reason =>
                        #{key => r, reason => {invalid_format, Value}}}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.7.2
decode_rsa_oth(d, Data, State) ->
  case maps:find(<<"d">>, Data) of
    error ->
      throw({error, #{key => oth, reason => #{key => d, reason => missing}}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, D} ->
          State1 = State#{d => bytes_integer(D)},
          decode_rsa_oth(t, Data, State1);
        {error, Reason} ->
          throw({error, #{key => oth, reason =>
                            #{key => d, reason => Reason}}})
      end;
    {ok, Value} ->
      throw({error, #{key => oth, reason =>
                        #{key => d, reason => {invalid_format, Value}}}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.7.3
decode_rsa_oth(t, Data, State) ->
  case maps:find(<<"t">>, Data) of
    error ->
      throw({error, #{key => oth, reason => #{key => t, reason => missing}}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, T} ->
          State#{t => bytes_integer(T)};
        {error, Reason} ->
          throw({error, #{key => oth, reason =>
                            #{key => t, reason => Reason}}})
      end;
    {ok, Value} ->
      throw({error, #{key => oth, reason =>
                        #{key => t, reason => {invalid_format, Value}}}})
  end.

%% https://tools.ietf.org/html/rfc7518#section-6.4
-spec decode_oct(map(), map()) -> jose_jwk:oct().
decode_oct(Data, State) ->
  decode_oct(k, Data, State).

%% https://tools.ietf.org/html/rfc7518#section-6.4.1
decode_oct(k, Data, State) ->
  case maps:find(<<"k">>, Data) of
    error ->
      throw({error, #{key => k, reason => missing}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, K} ->
          State#{k => K};
        {error, Reason} ->
          throw({error, #{key => k, reason => Reason}})
      end;
    {ok, Value} ->
      throw({error, #{key => k, reason => {invalid_format, Value}}})
  end.

-spec bytes_integer(binary()) ->
        non_neg_integer().
bytes_integer(Bin) when is_binary(Bin) ->
  Length = 8 * size(Bin),
  <<Int:Length>> = Bin,
  Int.

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
