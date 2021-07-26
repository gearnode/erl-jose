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

-module(jose_jwk_encoder).

-export([encode/2]).

-export_type([options/0]).

-type options() :: #{returns => binary | map}.

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
      | key_data.

-type state() :: #{}.

-spec encode(jose_jwk:jwk(), options()) -> binary() | map().
encode(JWK, Options) ->
  Data = encode(kty, JWK, Options, #{}),
  case maps:get(returns, Options, binary) of
    binary ->
      json:serialize(Data);
    map ->
      Data
  end.

-spec encode(step(), jose_jwk:jwk(), options(), state()) -> map().
%% https://tools.ietf.org/html/rfc7517#section-4.1
encode(kty, JWK, Options, State) ->
  State1 =
    case maps:get(kty, JWK) of
      oct ->
        State#{<<"kty">> => <<"oct">>};
      'RSA' ->
        State#{<<"kty">> => <<"RSA">>};
      'EC' ->
        State#{<<"kty">> => <<"EC">>}
    end,
  encode(use, JWK, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.2
encode(use, JWK, Options, State) ->
  State1 =
    case maps:find(use, JWK) of
      error ->
        State;
      {ok, sig} ->
        State#{<<"use">> => <<"sig">>};
      {ok, enc} ->
        State#{<<"use">> => <<"enc">>}
    end,
  encode(key_ops, JWK, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.3
encode(key_ops, JWK, Options, State) ->
  F = fun
        (sign) -> <<"sign">>;
        (verify) -> <<"verify">>;
        (encrypt) -> <<"encrypt">>;
        (decrypt) -> <<"decrypt">>;
        (wrapKey) -> <<"wrapKey">>;
        (unwrapKey) -> <<"unwrapKey">>;
        (deriveKey) -> <<"deriveKey">>;
        (deriveBits) -> <<"deriveBits">>
      end,
  State1 =
    case maps:find(key_ops, JWK) of
      error ->
        State;
      {ok, Operations} when is_list(Operations) ->
        Values = lists:map(F, Operations),
        State#{<<"key_ops">> => Values}
    end,
  encode(alg, JWK, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.4
encode(alg, JWK, Options, State) ->
  State1 =
    case maps:find(alg, JWK) of
      error ->
        State;
      {ok, Alg} ->
        Value = jose_jwa:encode_alg(Alg),
        State#{<<"alg">> => Value}
    end,
  encode(kid, JWK, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.5
encode(kid, JWK, Options, State) ->
  State1 =
    case maps:find(kid, JWK) of
      error ->
        State;
      {ok, Kid} when is_binary(Kid) ->
        State#{<<"kid">> => Kid}
    end,
  encode(x5u, JWK, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.6
encode(x5u, JWK, Options, State) ->
  State1 =
    case maps:find(x5u, JWK) of
      error ->
        State;
      {ok, _} ->
        %% TODO: implement me
        State
    end,
  encode(x5c, JWK, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.7
encode(x5c, JWK, Options, State) ->
  State1 =
    case maps:find(x5c, JWK) of
      error ->
        State;
      {ok, CertificateChain} when is_list(CertificateChain) ->
        Values = jose_x5c:encode(CertificateChain),
        State#{<<"x5c">> => Values}
    end,
  encode(x5t, JWK, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.8
encode(x5t, JWK, Options, State) ->
  State1 =
    case maps:find(x5t, JWK) of
      error ->
        State;
      {ok, SHA} ->
        State#{<<"x5t">> => jose_x5t:encode(SHA)}
    end,
  encode('x5t#S256', JWK, Options, State1);

%% https://tools.ietf.org/html/rfc7517#section-4.9
encode('x5t#S256', JWK, Options, State) ->
  State1 =
    case maps:find('x5t#S256', JWK) of
      error ->
        State;
      {ok, SHA} ->
        State#{<<"x5t#S256">> => jose_x5tS256:encode(SHA)}
    end,
  encode(key_data, JWK, Options, State1);

encode(key_data, JWK, Options, State) ->
  State.
