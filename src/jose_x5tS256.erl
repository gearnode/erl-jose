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

%% References:
%%
%% JWK -> https://tools.ietf.org/html/rfc7517#section-4.9
%% JWS -> https://tools.ietf.org/html/rfc7515#section-4.1.8
%% JWE -> https://tools.ietf.org/html/rfc7516#section-4.1.10
-module(jose_x5tS256).

-export([decode/1, encode/1]).

-export_type([decode_error_reason/0]).

-type decode_error_reason() ::
        invalid_format
      | {invalid_format, term()}.

-spec decode(binary()) ->
        {ok, binary()} | {error, decode_error_reason()}.
decode(Bin) when is_binary(Bin) ->
  case b64url:decode(Bin, [nopad]) of
    %% RFC 7517, Section 4.8 is ambiguous as to whether the digest output
    %% should be byte or hex. Available implementations use byte other use
    %% hex. To be compatible with all library we support both.
    {ok, Hex} when byte_size(Hex) =:= 64 ->
      try
        {ok, binary:decode_hex(Hex)}
      catch
        error:badarg ->
          {error, invalid_format}
      end;
    {ok, Thumbprint} when byte_size(Thumbprint) =:= 32 ->
      {ok, Thumbprint};
    {ok, _} ->
      {error, {invalid_format, invalid_sha2}};
    {error, Reason} ->
      {error, {invalid_format, Reason}}
  end;
decode(_) ->
  {error, invalid_format}.

-spec encode(jose:certificate_thumbprint()) -> binary().
encode(SHA) ->
  b64url:encode(SHA, [nopad]).
