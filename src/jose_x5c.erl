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

-module(jose_x5c).

-include_lib("public_key/include/public_key.hrl").

-export([decode/1]).

-export_type([encoded_chain/0, decoded_chain/0,
              decode_error_reason/0]).
              

-type encoded_chain() :: [binary()].
-type decoded_chain() :: [#'OTPCertificate'{}].
-type decode_error_reason() :: invalid_format | {invalid_format, term()}.

%% References:
%%
%% JWK -> https://tools.ietf.org/html/rfc7517#section-4.7
%% JWS -> https://tools.ietf.org/html/rfc7515#section-4.1.6
%% JWE -> https://tools.ietf.org/html/rfc7516#section-4.1.8
-spec decode(encoded_chain()) ->
        {ok, decoded_chain()} | {error, decode_error_reason()}.
decode(Value) when is_list(Value) ->
  case decode(Value, []) of
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
decode(_) ->
  {error, invalid_format}.

-spec decode(encoded_chain(), Acc) ->
        {ok, Acc} | {error, decode_error_reason()}
          when Acc :: decoded_chain().
decode([], Acc) ->
  {ok, Acc};
decode([H | T], Acc) when is_binary(H) ->
  case b64:decode(H) of
    {ok, Der} ->
      try
        Cert = public_key:pkix_decode_cert(Der, otp),
        decode(T, [Cert | Acc])
      catch
        {error, Reason} ->
          {error, {invalid_format, Reason}}
      end;
    {error, Reason} ->
      {error, {invalid_format, Reason}}
  end;
decode(_, _) ->
  {error, invalid_format}.
     
    
