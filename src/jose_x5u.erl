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

-module(jose_x5u).

-include_lib("public_key/include/public_key.hrl").

-export([decode/2]).

-export_type([cert_chain/0,
              decode_error_reason/0]).

-type fingerprint() :: binary().
-type decode_options() :: #{cacertfile => binary(),
                            certificates => [fingerprint()],
                            public_keys => [fingerprint()]}.

-type cert_chain() :: [#'OTPCertificate'{}].
-type decode_error_reason() ::
        invalid_format
      | {invalid_format, term()}
      | {bad_cert, term()}
      | {unavailable_service, term()}.

%% References:
%%
%% JWK -> https://tools.ietf.org/html/rfc7517#section-4.6
%% JWS -> https://tools.ietf.org/html/rfc7515#section-4.1.5
%% JWE -> https://tools.ietf.org/html/rfc7516#section-4.1.7
-spec decode(binary(), decode_options()) ->
        {ok, cert_chain()} | {error, decode_error_reason()}.
decode(Value, Options) when is_binary(Value), is_map(Options) ->
  case uri:parse(Value) of
    {ok, _} ->
      case fetch(Value, Options) of
        {ok, Bin} ->
          case decode_pem(Bin) of
            {ok, []} ->
              {ok, []};
            {ok, [Root | Rest] = Chain} ->
              case public_key:pkix_path_validation(Root, Rest, []) of
                {ok, {_, _}} ->
                  %% TODO: validate CRL
                  {ok, Chain};
                {error, {bad_cert, Reason}} ->
                  {error, {bad_cert, Reason}}
              end;
            {error, Reason} ->
              {error, Reason}
          end;
        {error, Reason} ->
          {error, Reason}
      end;
    {error, Reason} ->
      {error, {invalid_format, Reason}}
  end;
decode(_, _) ->
  {error, invalid_format}.

-spec fetch(binary(), decode_options()) ->
        {ok, binary()} | {error, {unavailable_service, term()}}.
fetch(URI, Options) ->
  RetOpts = [{body_format, binary}],
  CACertFile = maps:get(cacertfile, Options, ""),
  %% TODO: check CRL
  SSLOpts = [{cacertfile, CACertFile},
             {reuse_sessions, false},
             {verify_fun,
              {fun jose_verify_fun:verify/3, Options}}],
  case httpc:request(get, {URI, []}, [{ssl, SSLOpts}], RetOpts) of
    {ok, {{_, 200, "OK"}, _, Bin}} ->
      {ok, Bin};
    {ok, {{_, Code, _}, _, Bin}} ->
      {error, {unavailable_service, {bad_resp, Code, Bin}}};
    {error, Reason} ->
      {error, {unavailable_service, Reason}}
  end.

-spec decode_pem(binary()) ->
        {ok, cert_chain()} | {error, decode_error_reason()}.
decode_pem(Bin) ->
  Chain = public_key:pem_decode(Bin),
  decode_cert(Chain, []).

-spec decode_cert([public_key:pem_entry()], Acc) ->
        {ok, Acc} | {error, decode_error_reason()}
          when Acc :: cert_chain().
decode_cert([], Acc) ->
  {ok, Acc};
decode_cert([{'Certificate', Der, not_encrypted} | T], Acc) ->
  try
    Cert = public_key:pkix_decode_cert(Der, otp),
    decode_cert(T, [Cert | Acc])
  catch
    {error, Reason} ->
      {error, {invalid_format, Reason}}
  end;
decode_cert([{'Certificate', _, _} | _], _) ->
  {error, {invalid_format, encrypted_cert}};
decode_cert([{Type, _, _} | _], _) ->
  {error, {invalid_format, {bad_type, Type}}}.
