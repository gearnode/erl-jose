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

-module(jose_jwk_set).

-export([from_file/1, from_map/1]).

-export_type([set/0]).

-type set() :: #{keys := [jose:jwk()]}.

-spec from_file(file:filename_all()) -> {ok, set()} | {error, term()}.
from_file(Filename) ->
  case file:read_file(Filename) of
    {ok, File} ->
      case json:parse(File) of
        {ok, Data} ->
          from_map(Data);
        {error, Reason} ->
          {error, {invalid_format, Reason}}
      end;
    {error, Reason} ->
      {error, {invalid_file, Reason}}
  end.

-spec from_map(map()) -> {ok, set()} | {error, term()}.
from_map(#{<<"keys">> := Keys}) when is_list(Keys) ->
  F = fun
        (Key) when is_map(Key) ->
          case jose_jwk:decode(Key) of
            {ok, JWK} ->
              JWK;
            {error, Reason} ->
              throw({error, Reason})
          end;
        (_) ->
          throw({error, invalid_format})
      end,
  try
    lists:reverse(lists:map(F, Keys))
  catch
    throw:{error, Reason} ->
      {error, Reason}
  end;
from_map(_) ->
  {error, invalid_format}.
