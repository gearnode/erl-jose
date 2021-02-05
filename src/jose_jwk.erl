%% Copyright (c) 2020-2021 Bryan Frimin <bryan@frimin.fr>.
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

-include_lib("public_key/include/public_key.hrl").

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

-type header() ::
        #{kty := kty(),
          use => use(),
          key_ops => key_ops(),
          alg => jose_jwa:alg(),
          kid => jose:kid(),
          x5u => uri:uri(),
          x5c => [jose:certificate()],
          x5t => jose:certificate_thumbprint(),
          'x5t#S256' => jose:certificate_thumbprint()}.

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

-type decode_options() :: #{}.

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
decode(Data, _Options) when is_map(Data) ->
  try
    {ParseF, DecodeF} =
      case maps:find(<<"kty">>, Data) of
        error ->
          throw({error, {invalid_parameter, kty, unsupported}});
        {ok, <<"RSA">>} ->
          {fun parse_rsa/3, fun decode_rsa/1};
        {ok, <<"EC">>} ->
          {fun parse_ec/3, fun decode_ec/1};
        {ok, <<"oct">>} ->
          {fun parse_oct/3, fun decode_oct/1}
        end,
    MetadataKeys = [kty, use, key_ops, alg, kid, x5u, x5c, x5t, 'x5t#S256'],
    Parameters = maps:fold(ParseF, #{}, Data),
    Metadata = maps:with(MetadataKeys, Parameters),
    Data = maps:without(MetadataKeys, Parameters),
    {ok, Metadata, Data}
  catch
    throw:{error, Reason} ->
      {error, Reason}
  end.

decode_rsa(modulus, #{n := N}, PubKey) ->
  decode_rsa(exponent, Data, PubKey#'RSAPublicKey'{modulus=N});
decode_rsa(modulus, _Data, _State) ->
  throw({error, {invalid_key, {missing_key, n}, rsa}});

decode_rsa(exponent, #{e := E}, PubKey) ->
  decode_rsa(private_exponent, Data, PubKey#'RSAPublicKey'{publicExponent=E});
decode_rsa(exponent, _Data, _State) ->
  throw({error, {invalid_key, {missing_key, e}, rsa}});

decode_rsa(private_exponent, #{d := D}, PubKey) ->
  #'RSAPrivateKey'{version='two-prime',
                   modulus=PubKey#'RSAPublicKey'.modulus,
                   publicExponent=PubKey#'RSAPublicKey'.publicExponent,
                   privateExponent=D},
  {PubKey, PrivKey};
decode_rsa(private_exponent, _Data, PubKey) ->
  {PubKey}.

decode_ec(curve, #{crv := 'P-256'} = Data, State) ->
  Curve = pubkey_cert_records:namedCurves(secp256r1),
  decode_ec(x_coordinate, Data, State#{crv => Curve});
decode_ec(curve, #{crv := 'P-384'} = Data, State) ->
  Curve = pubkey_cert_records:namedCurves(secp384r1),
  decode_ec(x_coordinate, Data, State#{crv => Curve});
decode_ec(curve, #{crv := 'P-521'} = Data, State) ->
  Curve = pubkey_cert_records:namedCurves(secp521r1),
  decode_ec(x_coordinate, Data, State#{crv => Curve});

decode_ec(x_coordinate, #{x := X} = Data, #{crv := Crv} = State) when
    Crv =:= 'P-256', byte_size(X) =:= 32;
    Crv =:= 'P-384', byte_size(X) =:= 48;
    Crv =:= 'P-521', byte_size(X) =:= 66 ->
  decode_ec(y_coordinate, Data, State#{x => X});
decode_ec(x_coordiante, #{x := _}, _State) ->
  throw({error, {invalid_key, {invalid_format, x}, rsa}});
decoce_ec(x_coordiante, _Data, _State) ->
  throw({error, {invalid_key, {missing_key, n}, rsa}});

decode_ec(y_coordiante, #{y := Y} = Data, #{crv := Crv} = State) when
    Crv =:= 'P-256', byte_size(Y) =:= 32;
    Crv =:= 'P-384', byte_size(Y) =:= 48;
    Crv =:= 'P-521', byte_size(Y) =:= 66 ->
  decode_ec(ecc_private_key, Data, State#{y := Y});
decode_ec(y_coordinate, #{y := _}, _State) ->
  throw({error, {invalid_key, {invalid_format, x}, rsa}});
decode_ec(y_coordinate, _Data, _State) ->
  throw({error, {invalid_key, {missing_key, n}, rsa}});
decode_ec(ecc_private_key, #{d := D}, #{crv := Crv, x:= X, y := Y}) ->
  Priv = #'ECPrivateKey'{
            publicKey = <<16#04, X/binary, Y/binary>>,
            privateKey=D,
            parameters=Crv},
  Pub = {#'ECpoint'{point=Priv#'ECPrivateKey'.publicKey}, Crv},
  {Pub, Priv}.
%% decode_ec(ecc_private_key, _Data, #{crv = Crv, x := X, y := Y}) ->
%%   Pub = {#'ECPoint'{point=<<16#04,  X/binary, Y/binary>>}, Crv},
%%   {Pub}.

decode_oct(key_value, #{k := K}, State) ->
  {'SymmetricKey', K};
decode_oct(key_value, _Data, _State) ->
  throw({error, {invalid_key, {missing_key, n}, rsa}}).

-spec parse_parameters(map()) ->
          jwk().
parse_parameters(Data) -> 
  Fun =
    case maps:find(<<"kty">>, Data) of
      error ->
        throw({error, {invalid_parameter, kty, unsupported}});
      {ok, <<"RSA">>} ->
        fun parse_rsa/3;
      {ok, <<"EC">>} ->
        fun parse_ec/3;
      {ok, <<"oct">>} ->
        fun parse_oct/3
    end,
  maps:fold(Fun, #{}, Data).

-spec parse_parameter(json:key(), json:value(), map()) ->
        #{json:value() => term()}.
parse_parameter(<<"use">>, <<"enc">>, JWK) -> 
  JWK#{use => enc};
parse_parameter(<<"use">>, <<"sig">>, JWK) ->
  JWK#{use => sig};
parse_parameter(<<"use">>, Value, _JWK) when is_binary(Value) ->
  throw({error, {invalid_parameter, use, unsupported}});
parse_parameter(<<"use">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, use, invalid_format}});
parse_parameter(<<"key_ops">>, Values, JWK) when is_list(Values) ->
  JWK#{key_ops => lists:map(fun parse_key_ops_parameter/1, Values)};
parse_parameter(<<"key_ops">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, key_ops, invalid_format}});
parse_parameter(<<"alg">>, Value, JWK) when is_binary(Value) ->
  case jose_jwa:decode_alg(Value) of
    {ok, Alg} -> JWK#{alg => Alg};
    {error, Reason} -> throw({error, {invalid_parameter, alg, Reason}})
  end;
parse_parameter(<<"alg">>, _Alg, _JWK) ->
  throw({error, {invalid_parameter, alg, invalid_format}});
parse_parameter(<<"kid">>, Value, JWK)
 when is_binary(Value) ->
  JWK#{kid => Value};
parse_parameter(<<"kid">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, kid, invalid_format}});
parse_parameter(<<"x5u">>, Value, JWK) when is_binary(Value) ->
  case uri:parse(Value) of
    {ok, URI} ->
      JWK#{x5u => URI};
    {error, Reason} ->
      throw({error, {invalid_parameter, x5u, Reason}})
  end;
parse_parameter(<<"x5u">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, x5u, invalid_format}});
parse_parameter(<<"x5c">>, [], _JWK) ->
  throw({error, {invalid_parameter, x5c, invalid_format}});
parse_parameter(<<"x5c">>, Values, JWK) when is_list(Values) ->
  Chain = parse_x5c_parameter(Values, []),
  JWK#{x5c => Chain};
parse_parameter(<<"x5c">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, x5c, invalid_format}});
parse_parameter(<<"x5t">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value) of
    {ok, Thumbprint} when byte_size(Thumbprint) =:= 20 ->
      JWK#{x5t => Thumbprint};
    {ok, _} ->
      throw({error, {invalid_parameter, x5t, invalid_format}});
    {error, Reason} ->
      throw({error, {invalid_parameter, x5t, Reason}})
  end;
parse_parameter(<<"x5t">>, _Value, _Header) ->
  throw({error, {invalid_parameter, x5t, invalid_format}});
parse_parameter(<<"x5t#S256">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value) of
    {ok, Thumbprint} when byte_size(Thumbprint) =:= 32 ->
      JWK#{'x5t#S256' => Thumbprint};
    {ok, _} ->
      throw({error, {invalid_parameter, 'x5t#S256', invalid_format}});
    {error, Reason} ->
      throw({error, {invalid_parameter, 'x5t#S256', Reason}})
  end;
parse_parameter(<<"x5t#S256">>, _Value, _JWK) ->
  throw({error, {invalid_header, 'x5t#S256', invalid_format}});
parse_parameter(Key, _Value, _JWK) ->
  throw({error, {unknown_parameter, Key}}).

-spec parse_ec(json:key(), json:value(), map()) ->
        ec().
parse_ec(<<"kty">>, <<"EC">>, JWK) ->
  JWK#{kty => 'EC'};
parse_ec(<<"kty">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, unsupported_kty}});
parse_ec(<<"crv">>, <<"P-256">>, JWK) ->
  JWK#{crv => 'P-256'};
parse_ec(<<"crv">>, <<"P-384">>, JWK) ->
  JWK#{crv => 'P-384'};
parse_ec(<<"crv">>, <<"P-512">>, JWK) ->
  JWK#{crv => 'P-512'};
parse_ec(<<"crv">>, Value, _JWK) when is_binary(Value) ->
  throw({error, {invalid_parameter, crv, unsupported}});
parse_ec(<<"crv">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, crv, invalid_format}});
parse_ec(<<"x">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value, #{padding => false}) of
    {ok, Decoded} ->
      JWK#{x => Decoded};
    {error, Reason} ->
      throw({error, {invalid_parameter, x, Reason}})
  end;
parse_ec(<<"x">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, x, invalid_format}});
parse_ec(<<"y">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value, #{padding => false}) of
    {ok, Decoded} ->
      JWK#{y => Decoded};
    {error, Reason} ->
      throw({error, {invalid_parameter, y, Reason}})
  end;
parse_ec(<<"y">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, y, invalid_format}});
parse_ec(<<"d">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value, #{padding => false}) of
    {ok, Decoded} ->
      JWK#{d => Decoded};
    {error, Reason} ->
      throw({error, {invalid_parameter, d, Reason}})
  end;
parse_ec(<<"d">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, d, invalid_format}});
parse_ec(Key, Value, JWK) ->
  parse_parameter(Key, Value, JWK).

-spec parse_oct(json:key(), json:value(), map()) ->
        oct().
parse_oct(<<"kty">>, <<"oct">>, JWK) ->
  JWK#{kty => oct};
parse_oct(<<"kty">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, unsupported_kty}});
parse_oct(<<"k">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value, #{padding => false}) of
    {ok, Decoded} ->
      JWK#{k => Decoded};
    {error, Reason} ->
      throw({error, {invalid_parameter, k, Reason}})
  end;
parse_oct(<<"k">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, k, invalid_format}});
parse_oct(Key, Value, JWK) ->
  parse_parameter(Key, Value, JWK).

-spec parse_rsa(json:key(), json:value(), map()) ->
        rsa().
parse_rsa(<<"kty">>, <<"RSA">>, JWK) ->
  JWK#{kty => 'RSA'};
parse_rsa(<<"kty">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, unsupported_kty}});
parse_rsa(<<"n">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value, #{padding => false}) of
    {ok, Decoded} ->
      JWK#{n => bytes_integer(Decoded)};
    {error, Reason} ->
      throw({error, {invalid_parameter, n, Reason}})
  end;
parse_rsa(<<"n">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, n, invalid_format}});
parse_rsa(<<"e">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value, #{padding => false}) of
    {ok, Decoded} ->
      JWK#{e => bytes_integer(Decoded)};
    {error, Reason} ->
      throw({error, {invalid_parameter, e, Reason}})
  end;
parse_rsa(<<"e">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, e, invalid_format}});
parse_rsa(<<"d">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value, #{padding => false}) of
    {ok, Decoded} ->
      JWK#{d => bytes_integer(Decoded)};
    {error, Reason} ->
      throw({error, {invalid_parameter, d, Reason}})
  end;
parse_rsa(<<"d">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, d, invalid_format}});
parse_rsa(<<"p">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value, #{padding => false}) of
    {ok, Decoded} ->
      JWK#{p => bytes_integer(Decoded)};
    {error, Reason} ->
      throw({error, {invalid_parameter, p, Reason}})
  end;
parse_rsa(<<"p">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, p, invalid_format}});
parse_rsa(<<"q">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value, #{padding => false})  of
    {ok, Decoded} ->
      JWK#{q => bytes_integer(Decoded)};
    {error, Reason} ->
      throw({error, {invalid_parameter, q, Reason}})
  end;
parse_rsa(<<"q">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, q, invalid_format}});
parse_rsa(<<"dp">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value, #{padding => false}) of
    {ok, Decoded} ->
      JWK#{dp => bytes_integer(Decoded)};
    {error, Reason} ->
      throw({error, {invalid_parameter, dp, Reason}})
  end;
parse_rsa(<<"dp">>, _Value, _JWK) ->
  throw({error, {invalid_format, dp, invalid_format}});
parse_rsa(<<"dq">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value, #{padding => false}) of
    {ok, Decoded} ->
      JWK#{dq => bytes_integer(Decoded)};
    {error, Reason} ->
      throw({error, {invalid_parameter, dq, Reason}})
  end;
parse_rsa(<<"dq">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, dq, invalid_format}});
parse_rsa(<<"qi">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value, #{padding => false}) of
    {ok, Decoded} ->
      JWK#{qi => bytes_integer(Decoded)};
    {error, Reason} ->
      throw({error, {invalid_parameter, qi, Reason}})
  end;
parse_rsa(<<"qi">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, qi, invalid_format}});
parse_rsa(<<"oth">>, Values, JWK) when is_list(Values) ->
  JWK#{oth => lists:map(fun parse_oth_parameter/1, Values)};
parse_rsa(<<"oth">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, oth, invalid_format}});
parse_rsa(<<"k">>, Value, JWK) when is_binary(Value) ->
  case jose_base64url:decode(Value, #{padding => false}) of
    {ok, Decoded} ->
      JWK#{k => Decoded};
    {error, Reason} ->
      throw({error, {invalid_parameter, k, Reason}})
  end;
parse_rsa(<<"k">>, _Value, _JWK) ->
  throw({error, {invalid_parameter, k, invalid_format}});
parse_rsa(Key, Value, JWK) ->
  parse_parameter(Key, Value, JWK).

-spec parse_oth_parameter(map()) ->
        oth().
parse_oth_parameter(#{<<"r">> := R, <<"d">> := D, <<"t">> := T}) ->
  #{r => bytes_integer(R), d => bytes_integer(D), t => bytes_integer(T)};
parse_oth_parameter(_) ->
  throw({error, {invalid_parameter, oth, invalid_format}}).

-spec parse_key_ops_parameter(binary()) ->
        key_ops().
parse_key_ops_parameter(<<"sign">>) ->
  sign;
parse_key_ops_parameter(<<"verify">>) ->
  verify;
parse_key_ops_parameter(<<"encrypt">>) ->
  encrypt;
parse_key_ops_parameter(<<"decrypt">>) ->
  decrypt;
parse_key_ops_parameter(<<"wrapKey">>) ->
  wrapKey;
parse_key_ops_parameter(<<"unwrapKey">>) ->
  unwrapKey;
parse_key_ops_parameter(<<"deriveKey">>) ->
  deriveKey;
parse_key_ops_parameter(<<"deriveBits">>) ->
  deriveBits;
parse_key_ops_parameter(Value) when is_binary(Value) ->
  throw({error, {invalid_parameter, key_ops, unsupported}});
parse_key_ops_parameter(_Value) ->
  throw({error, {invalid_parameter, key_ops, invalid_format}}).

-spec parse_x5c_parameter([binary()], [jose:certificate()]) ->
        [jose:certificate()].
parse_x5c_parameter([], Acc) ->
  lists:reverse(Acc);
parse_x5c_parameter([H | T], Acc) when is_binary(H) ->
  case jose_base64:decode(H) of
    {ok, Data} ->
      Cert =
        try public_key:pkix_decode_cert(Data, otp)
        catch error:Reason ->
            throw({error, {invalid_parameter, x5c, Reason}})
        end,
      parse_x5c_parameter(T, [Cert | Acc]);
    {error, Reason} ->
      throw({error, {invalid_parameter, x5c, Reason}})
  end;
parse_x5c_parameter(_Value, _Acc) ->
  throw({error, {invalid_parameter, x5c, invalid_format}}).

-spec bytes_integer(binary()) ->
        non_neg_integer().
bytes_integer(Bin) when is_binary(Bin) ->
  Length = 8 * size(Bin),
  <<Int:Length>> = Bin,
  Int.
