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
    {ok, parse_parameters(Data)}
  catch
    throw:{error, Reason} ->
      {error, Reason}
  end.

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
parse_parameter(<<"kid">>, Value, JWK) when is_binary(Value) ->
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
      JWK#{n => bytes_integer(Decoded)};
    {error, Reason} ->
      throw({error, {invalid_parameter, k, Reason}})
  end;
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

%% #{<<"kty">> => <<"oct">>, <<"alg">> => <<"A128KW">>, <<"k">> => <<"GawgguFyGrWKav7AX4VKUg">>}

%% #{<<"kty">> => <<"RSA">>, <<"n">> => <<"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw">>, <<"e">> => <<"AQAB">>}

%% #{<<"kty">> => <<"RSA">>,<<"kid">> => <<"cc34c0a0-bd5a-4a3c-a50d-a2a7db7643df">>,<<"use">> => <<"sig">>,<<"n">>   => <<"pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w">>,<<"e">>   => <<"AQAB">>,<<"d">>   => <<"ksDmucdMJXkFGZxiomNHnroOZxe8AmDLDGO1vhs-POa5PZM7mtUPonxwjVmthmpbZzla-kg55OFfO7YcXhg-Hm2OWTKwm73_rLh3JavaHjvBqsVKuorX3V3RYkSro6HyYIzFJ1Ek7sLxbjDRcDOj4ievSX0oN9l-JZhaDYlPlci5uJsoqro_YrE0PRRWVhtGynd-_aWgQv1YzkfZuMD-hJtDi1Im2humOWxA4eZrFs9eG-whXcOvaSwO4sSGbS99ecQZHM2TcdXeAs1PvjVgQ_dKnZlGN3lTWoWfQP55Z7Tgt8Nf1q4ZAKd-NlMe-7iqCFfsnFwXjSiaOa2CRGZn-Q">>,<<"p">>   => <<"4A5nU4ahEww7B65yuzmGeCUUi8ikWzv1C81pSyUKvKzu8CX41hp9J6oRaLGesKImYiuVQK47FhZ--wwfpRwHvSxtNU9qXb8ewo-BvadyO1eVrIk4tNV543QlSe7pQAoJGkxCia5rfznAE3InKF4JvIlchyqs0RQ8wx7lULqwnn0">>,<<"q">>   => <<"ven83GM6SfrmO-TBHbjTk6JhP_3CMsIvmSdo4KrbQNvp4vHO3w1_0zJ3URkmkYGhz2tgPlfd7v1l2I6QkIh4Bumdj6FyFZEBpxjE4MpfdNVcNINvVj87cLyTRmIcaGxmfylY7QErP8GFA-k4UoH_eQmGKGK44TRzYj5hZYGWIC8">>,<<"dp">>  => <<"lmmU_AG5SGxBhJqb8wxfNXDPJjf__i92BgJT2Vp4pskBbr5PGoyV0HbfUQVMnw977RONEurkR6O6gxZUeCclGt4kQlGZ-m0_XSWx13v9t9DIbheAtgVJ2mQyVDvK4m7aRYlEceFh0PsX8vYDS5o1txgPwb3oXkPTtrmbAGMUBpE">>,<<"dq">>  => <<"mxRTU3QDyR2EnCv0Nl0TCF90oliJGAHR9HJmBe__EjuCBbwHfcT8OG3hWOv8vpzokQPRl5cQt3NckzX3fs6xlJN4Ai2Hh2zduKFVQ2p-AF2p6Yfahscjtq-GY9cB85NxLy2IXCC0PF--Sq9LOrTE9QV988SJy_yUrAjcZ5MmECk">>,<<"qi">>  => <<"ldHXIrEmMZVaNwGzDF9WG8sHj2mOZmQpw9yrjLK9hAsmsNr5LTyqWAqJIYZSwPTYWhY4nu2O0EY9G9uYiqewXfCKw_UngrJt8Xwfq1Zruz0YY869zPN4GiE9-9rzdZB33RBw8kIOquY3MK74FMwCihYx_LiU2YTHkaoJ3ncvtvg">>}
