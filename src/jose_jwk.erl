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

-module(jose_jwk).

-export([decode/1]).

-export_type([jwk/0,
              rsa/0,
              ec/0,
              oct/0,
              type/0,
              use/0,
              key_ops/0,
              crv/0,
              coordinate/0,
              ecc_private_key/0,
              modulus/0,
              exponent/0,
              prime_factor/0,
              oth/0]).

-type jwk() :: oct() | rsa() | ec().

-type ec() :: ec_public() | ec_private().

-type ec_public() ::
        #{kty := 'EC',
          use => use(),
          key_ops => key_ops(),
          alg => jose_jwa:alg(),
          kid => jose:kid(),
          x5u => uri:uri(),
          x5c => [jose:certificate()],
          x5t => jose:certificate_thumbprint(),
          'x5t#S256' => jose:certificate_thumbprint(),
          crv := crv(),
          x := coordinate(),
          y => coordinate()}.

-type ec_private() :: 
        #{kty := 'EC',
          use => use(),
          key_ops => key_ops(),
          alg => jose_jwa:alg(),
          kid => jose:kid(),
          x5u => uri:uri(),
          x5c => [jose:certificate()],
          x5t => jose:certificate_thumbprint(),
          'x5t#S256' => jose:certificate_thumbprint(),
          crv := crv(),
          x := coordinate(),
          y => coordinate(),
          d := ecc_private_key()}.

-type rsa() :: rsa_public() | rsa_private().

-type rsa_public() ::
        #{kty := 'RSA',
          use => use(),
          key_ops => key_ops(),
          alg => jose_jwa:alg(),
          kid => jose:kid(),
          x5u => uri:uri(),
          x5c => [jose:certificate()],
          x5t => jose:certificate_thumbprint(),
          'x5t#S256' => jose:certificate_thumbprint(),
          n := modulus(),
          e := exponent()}.

-type rsa_private() ::
        #{kty := 'RSA',
          use => use(),
          key_ops => key_ops(),
          alg => jose_jwa:alg(),
          kid => jose:kid(),
          x5u => uri:uri(),
          x5c => [jose:certificate()],
          x5t => jose:certificate_thumbprint(),
          'x5t#S256' => jose:certificate_thumbprint(),
          n := modulus(),
          e := exponent(),
          d := exponent(),
          p => prime_factor(),
          q => prime_factor(),
          dp => exponent(),
          dq => exponent(),
          qi => non_neg_integer(),
          oth => [oth()]}.

-type oct() ::
        #{kty := oct,
          use => use(),
          key_ops => key_ops(),
          alg => jose_jwa:alg(),
          kid => jose:kid(),
          x5u => uri:uri(),
          x5c => [jose:certificate()],
          x5t => jose:certificate_thumbprint(),
          'x5t#S256' => jose:certificate_thumbprint(),
          k := binary()}.


% https://www.iana.org/assignments/jose/jose.xhtml#web-key-types
-type type() :: 'RSA' | 'EC' | oct.

% https://www.iana.org/assignments/jose/jose.xhtml#web-key-use
-type use() :: sig | enc.

-type key_ops() ::
        sign
      | verify
      | encrypt
      | decrypt
      | wrapKey
      | unwrapKey
      | deriveKey
      | deriveBits.

% https://www.iana.org/assignments/jose/jose.xhtml#web-key-elliptic-curve
-type crv() ::
        'P-256'
      | 'P-384'
      | 'P-521'.

-type coordinate() :: binary().
-type ecc_private_key() :: binary().
-type modulus() :: non_neg_integer().
-type exponent() :: non_neg_integer().
-type prime_factor() :: non_neg_integer().
-type oth() :: #{r := prime_factor(),
                 d := exponent(),
                 t := non_neg_integer()}.

-type fingerprint() :: binary().
-type decode_options() ::
        #{trusted_remotes =>
            #{cacertfile => file:filename_all(),
              certificates => [fingerprint()],
              public_keys => [fingerprint()]},
         certificate_store => gen_server_ref()}.

-type gen_server_ref() ::
        term()
      | {term(), atom()}
      | {global, term()}
      | {via, atom(), term()}
      | pid().

-spec decode(binary() | map()) ->
        {ok, jwk()} | {error, term()}.
decode(Term) ->
  decode(Term, #{}).

-spec decode(binary() | map(), decode_options()) ->
        {ok, jwk()} | {error, term()}.
decode(Bin, Options) when is_binary(Bin) ->
  case json:parse(Bin, #{duplicate_key_handling => error}) of
    {ok, Data} when is_map(Data) ->
      decode(Data, Options);
    {ok, _} ->
      {error, invalid_format};
    {error, Reason} ->
      {error, {invalid_format, Reason}}
  end;
decode(Data, Options) when is_map(Data) ->
  try
    decode(kty, Data, Options, #{})
  catch
    throw:{error, Reason} ->
      {error, Reason}
  end.

-spec decode(atom(), map(), decode_options(), map()) -> jwk().
%% https://tools.ietf.org/html/rfc7517#section-4.1
decode(kty, Data, Options, State) ->
  Kty =
    case maps:find(<<"kty">>, Data) of
      error ->
        throw({error, {missing_parameter, kty}});
      {ok, <<"oct">>} ->
        oct;
      {ok, <<"RSA">>} ->
        'RSA';
      {ok, <<"EC">>} ->
        'EC';
      {ok, Value} ->
        throw({error, {invalid_parameter, {unsupported, Value}, kty}})
    end,
  decode(use, Data, Options, State#{kty => Kty});

%% https://tools.ietf.org/html/rfc7517#section-4.2
decode(use, Data, Options, State) ->
  State1 =
    case maps:find(<<"use">>, Data) of
      error ->
        State;
      {ok, <<"sig">>} ->
        State#{use => sig};
      {ok, <<"enc">>} ->
        State#{use => enc};
      {ok, Value} when is_binary(Value) ->
        throw({error, {invalid_parameter, {unsupported, Value}, use}});
      {ok, Value} ->
        throw({error, {invalid_parameter, {invalid_syntax, Value}, use}})
    end,
  decode(key_ops, Data, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.3
decode(key_ops, Data, Options, State) ->
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
          throw({error, {invalid_parameter, {unsupported, Value}, key_ops}});
        (Value) ->
          throw({error, {invalid_parameter, {invalid_syntax, Value}, key_ops}})
      end,
  State1 =
    case maps:find(<<"key_ops">>, Data) of
      error ->
        State;
      {ok, Value} when is_list(Value) ->
        Operations = lists:map(F, Value),
        State#{key_ops => Operations};
      {ok, Value} ->
        throw({error, {invalid_parameter, {unsupported, Value}, key_ops}})
    end,
  decode(alg, Data, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.4
decode(alg, Data, Options, State) ->
  State1 =
    case maps:find(<<"alg">>, Data) of
      error ->
        State;
      {ok, Value} when is_binary(Value) ->
        case jose_jwa:decode_alg(Value) of
          {ok, Alg} ->
            State#{alg => Alg};
          {error, Reason} ->
            throw({error, {invalid_parameter, Reason, alg}})
        end;
      {ok, Value} ->
        throw({error, {invalid_parameter, {invalid_syntax, Value}, alg}})
    end,
  decode(kid, Data, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.5
decode(kid, Data, Options, State) ->
  State1 =
    case maps:find(<<"kid">>, Data) of
      error ->
        State;
      {ok, Kid} when is_binary(Kid) ->
        State#{kid => Kid};
      {ok, Value} ->
        throw({error, {invalid_parameter, {invalid_syntax, Value}, kid}})
    end,
  decode(x5u, Data, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.6
decode(x5u, Data, Options, State) ->
  State1 =
    case maps:find(<<"x5u">>, Data) of
      error ->
        State;
      {ok, Value} ->
        TrustedRemotes = maps:get(trusted_remotes, Options, #{}),
        case jose_x5u:decode(Value, TrustedRemotes) of
          {ok, []} ->
            State;
          {ok, [Root | _] = Chain} ->
            CertStore =
              maps:get(certificate_store, Options, certificate_store_default),
            case jose_certificate_store:find(CertStore, Root) of
              {ok, _} ->
                %% TODO: ensure x5t match with x5u certificate.
                State#{x5c => Chain};
              error ->
                throw({error,
                       {invalid_parameter, {bad_cert, untrusted_cert}, x5u}})
            end;
          {error, Reason} ->
            throw({error, {invalid_parameter, Reason, x5c}})
        end
    end,
  decode(x5c, Data, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.7
decode(x5c, Data, Options, State) ->
  State1 =
    case maps:find(<<"x5c">>, Data) of
      error ->
        State;
      {ok, Value} ->
        case jose_x5c:decode(Value) of
          {ok, []} ->
            State;
          {ok, [Root | _] = Chain} ->
            CertStore =
              maps:get(certificate_store, Options, certificate_store_default),
            case jose_certificate_store:find(CertStore, Root) of
              {ok, _} ->
                %% TODO: ensure x5t match with x5u certificate.
                State#{x5c => Chain};
              error ->
                throw({error,
                       {invalid_parameter, {bad_cert, untrusted_cert}, x5c}})
            end;
          {error, Reason} ->
            throw({error, {invalid_parameter, Reason, x5c}})
        end
    end,
  decode(x5t, Data, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.8
decode(x5t, Data, Options, State) ->
  State1 =
    case maps:find(<<"x5t">>, Data) of
      error ->
        State;
      {ok, Value} ->
        case jose_x5t:decode(Value) of
          {ok, Thumbprint} ->
            State#{x5t => Thumbprint};
          {error, Reason} ->
            throw({error, {invalid_parameter, Reason, x5t}})
        end
    end,
  decode('x5t#S256', Data, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.9
decode('x5t#S256', Data, _Options, State) ->
  State1 =
    case maps:find(<<"x5t#S256">>, Data) of
      error ->
        State;
      {ok, Value} ->
        case jose_x5tS256:decode(Value) of
          {ok, Thumbprint} ->
            State#{x5t => Thumbprint};
          {error, Reason} ->
            throw({error, {invalid_parameter, Reason, 'x5t#S256'}})
        end
    end,
  case maps:get(kty, State1) of
    oct ->
      decode_oct(Data, State1);
    'RSA' ->
      decode_rsa(Data, State1);
    'EC' ->
      decode_ec(Data, State1)
  end.

%% https://tools.ietf.org/html/rfc7518#section-6.2
-spec decode_ec(map(), map()) -> ec().
decode_ec(Data, State) ->
  decode_ec(crv, Data, State).

%% https://tools.ietf.org/html/rfc7518#section-6.2.1.1
decode_ec(crv, Data, State) ->
  State1 =
    case maps:find(<<"crv">>, Data) of
      error ->
        throw({error, {missing_parameter, crv}});
      {ok, <<"P-256">>} ->
        State#{crv => 'P-256'};
      {ok, <<"P-384">>} ->
        State#{crv => 'P-384'};
      {ok, <<"P-521">>} ->
        State#{crv => 'P-521'};
      {ok, Value} when is_binary(Value) ->
        throw({error, {invalid_parameter, {unsupported, Value}, crv}});
      {ok, Value} ->
        throw({error, {invalid_parameter, {invalid_syntax, Value}, crv}})
    end,
  decode_ec(x, Data, State1);

%% https://tools.ietf.org/html/rfc7518#section-6.2.1.2
decode_ec(x, Data, #{crv := Crv} = State) ->
  State1 =
    case maps:find(<<"x">>, Data) of
      error ->
        throw({error, {missing_parameter, x}});
      {ok, Value} when is_binary(Value) ->
        case b64url:decode(Value, [nopad]) of
          {error, Reason} ->
            throw({error, {invalid_parameter, Reason, x}});
          {ok, X} when Crv =:= 'P-256', byte_size(X) =:= 32;
                       Crv =:= 'P-384', byte_size(X) =:= 48;
                       Crv =:= 'P-521', byte_size(X) =:= 66 ->
            State#{x => X};
          {ok, DV} ->
            throw({error, {invalid_parameter, {invalid_syntax, DV}, x}})
        end;
      {ok, Value} ->
        throw({error, {invalid_parameter, {invalid_syntax, Value}, x}})
    end,
  decode_ec(y, Data, State1);

%% https://tools.ietf.org/html/rfc7518#section-6.2.1.3
decode_ec(y, Data, #{crv := Crv} = State) ->
  State1 =
    case maps:find(<<"y">>, Data) of
      %% XXX: not all Elliptic Curve required the "y" paramater.
      error ->
        throw({error, {missing_parameter, y}});
      {ok, Value} when is_binary(Value) ->
        case b64url:decode(Value, [nopad]) of
          {error, Reason} ->
            throw({error, {invalid_parameter, Reason, y}});
          {ok, Y} when Crv =:= 'P-256', byte_size(Y) =:= 32;
                       Crv =:= 'P-384', byte_size(Y) =:= 48;
                       Crv =:= 'P-521', byte_size(Y) =:= 66 ->
            State#{y => Y};
          {ok, DV} ->
            throw({error, {invalid_parameter, {invalid_syntax, DV}, y}})
        end;
      {ok, Value} ->
        throw({error, {invalid_parameter, {invalid_syntax, Value}, y}})
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
          throw({error,
                 {invalid_parameter, Reason, d}});
        {ok, D} when is_binary(Value) ->
          %% TODO: check the size of the octect string.
          State#{d => D};
        {ok, DV} ->
          throw({error, {invalid_parameter, {invalid_syntax, DV}, y}})
      end;
    {ok, Value} ->
      throw({error, {invalid_parameter, {invalid_syntax, Value}, y}})
  end.

%% https://tools.ietf.org/html/rfc7518#section-6.3
-spec decode_rsa(map(), map()) -> rsa().
decode_rsa(Data, State) ->
  decode_rsa(n, Data, State).

%% https://tools.ietf.org/html/rfc7518#section-6.3.1.1
decode_rsa(n, Data, State) ->
  case maps:find(<<"n">>, Data) of
    error ->
      throw({error, {missing_parameter, n}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, N} ->
          State1 = State#{n => bytes_integer(N)},
          decode_rsa(e, Data, State1);
        {error, Reason} ->
          throw({error, {invalid_parameter, Reason, n}})
      end;
    {ok, Value} ->
      throw({error, {invalid_parameter, {invalid_syntax, Value}, n}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.1.2
decode_rsa(e, Data, State) ->
  case maps:find(<<"e">>, Data) of
    error ->
      throw({error, {missing_parameter, e}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, E} ->
          State1 = State#{e => bytes_integer(E)},
          decode_rsa(d, Data, State1);
        {error, Reason} ->
          throw({error, {invalid_parameter, Reason, e}})
      end;
    {ok, Value} ->
      throw({error, {invalid_parameter, {invalid_syntax, Value}, e}})
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
          throw({error, {invalid_parameter, Reason, d}})
      end;
    {ok, Value} ->
      throw({error, {invalid_parameter, {invalid_syntax, Value}, d}})
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
          throw({error, {invalid_parameter, Reason, p}})
      end;
    {ok, Value} ->
      throw({error, {invalid_parameter, {invalid_syntax, Value}, p}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.3
decode_rsa(q, Data, State) ->
  case maps:find(<<"q">>, Data) of
    error ->
      throw({error, {missing_parameter, q}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, Q} ->
          State1 = State#{q => bytes_integer(Q)},
          decode_rsa(dp, Data, State1);
        {error, Reason} ->
          throw({error, {invalid_parameter, Reason, q}})
      end;
    {ok, Value} ->
      throw({error, {invalid_parameter, {invalid_syntax, Value}, q}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.4
decode_rsa(dp, Data, State) ->
  case maps:find(<<"dp">>, Data) of
    error ->
      throw({error, {missing_parameter, dp}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, DP} ->
          State1 = State#{dp => bytes_integer(DP)},
          decode_rsa(dq, Data, State1);
        {error, Reason} ->
          throw({error, {invalid_parameter, Reason, dp}})
      end;
    {ok, Value} ->
      throw({error, {invalid_parameter, {invalid_syntax, Value}, dp}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.5
decode_rsa(dq, Data, State) ->
  case maps:find(<<"dq">>, Data) of
    error ->
      throw({error, {missing_parameter, dp}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, DQ} ->
          State1 = State#{dq => DQ},
          decode_rsa(qi, Data, State1);
        {error, Reason} ->
          throw({error, {invalid_parameter, Reason, dq}})
      end;
    {ok, Value} ->
      throw({error, {invalid_parameter, {invalid_syntax, Value}, dq}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.6
decode_rsa(qi, Data, State) ->
  case maps:find(<<"qi">>, Data) of
    error ->
      throw({error, {missing_parameter, dp}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, QI} ->
          State1 = State#{qi => QI},
          decode_rsa(oth, Data, State1);
        {error, Reason} ->
          throw({error, {invalid_parameter, Reason, qi}})
      end;
    {ok, Value} ->
      throw({error, {invalid_parameter, {invalid_syntax, Value}, qi}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.7
decode_rsa(oth, Data, State) ->
  case maps:find(<<"oth">>, Data) of
    error ->
      State;
    {ok, []} ->
      throw({error, {invalid_parameter, {invalid_syntax, []}, oth}});
    {ok, Value} when is_list(Value) ->
      F = fun (X) -> decode_rsa_oth(X, #{}) end,
      State#{oth => lists:map(F, Value)};
    {ok, Value} ->
      throw({error, {invalid_parameter, {invalid_syntax, Value}, oth}})
  end.

% https://tools.ietf.org/html/rfc7518#section-6.3.2.7.1
decode_rsa_oth(Data, State) ->
  decode_rsa_oth(r, Data, State).

decode_rsa_oth(r, Data, State) ->
  case maps:find(<<"r">>, Data) of
    error ->
      throw({error,
             {invalid_parameter,
              {invalid_member,
               missing_member, r}, oth}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, R} ->
          State1 = State#{r => R},
          decode_rsa_oth(d, Data, State1);
        {error, Reason} ->
          throw({error,
                 {invalid_parameter,
                  {invalid_member, Reason, r}, oth}})
      end;
    {ok, Value} ->
      throw({error,
             {invalid_parameter,
              {invalid_member,
               {invalid_syntax, Value}, r}, oth}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.7.2
decode_rsa_oth(d, Data, State) ->
  case maps:find(<<"d">>, Data) of
    error ->
      throw({error,
             {invalid_parameter,
              {invalid_member,
               missing_member, d}, oth}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, D} ->
          State1 = State#{d => D},
          decode_rsa_oth(t, Data, State1);
        {error, Reason} ->
          throw({error,
                 {invalid_parameter,
                  {invalid_member, Reason, d}, oth}})
      end;
    {ok, Value} ->
      throw({error,
             {invalid_parameter,
              {invalid_member,
               {invalid_syntax, Value}, d}, oth}})
  end;

%% https://tools.ietf.org/html/rfc7518#section-6.3.2.7.3
decode_rsa_oth(t, Data, State) ->
  case maps:find(<<"t">>, Data) of
    error ->
      throw({error,
             {invalid_parameter,
              {invalid_member,
               missing_member, t}, oth}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, T} ->
          State#{t => T};
        {error, Reason} ->
          throw({error,
                 {invalid_parameter,
                  {invalid_member, Reason, t}, oth}})
      end;
    {ok, Value} ->
      throw({error,
             {invalid_parameter,
              {invalid_member,
               {invalid_syntax, Value}, t}, oth}})
  end.

%% https://tools.ietf.org/html/rfc7518#section-6.4
-spec decode_oct(map(), map()) -> oct().
decode_oct(Data, State) ->
  decode_oct(k, Data, State).

%% https://tools.ietf.org/html/rfc7518#section-6.4.1
decode_oct(k, Data, State) ->
  case maps:find(<<"k">>, Data) of
    error ->
      throw({error, {missing_parameter, k}});
    {ok, Value} when is_binary(Value) ->
      case b64url:decode(Value, [nopad]) of
        {ok, K} ->
          State#{k => K};
        {error, Reason} ->
          throw({error, {invalid_parameter, Reason, k}})
      end;
    {ok, Value} ->
      throw({error, {invalid_parameter, {invalid_syntax, Value}, k}})
  end.

-spec bytes_integer(binary()) ->
        non_neg_integer().
bytes_integer(Bin) when is_binary(Bin) ->
  Length = 8 * size(Bin),
  <<Int:Length>> = Bin,
  Int.
