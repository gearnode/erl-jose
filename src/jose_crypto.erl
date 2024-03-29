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

-module(jose_crypto).

-include_lib("public_key/include/public_key.hrl").

-export([ec_point_to_coordinate/1, ec_coordinate_to_point/2,
         get_ec_curve/1]).

-spec ec_point_to_coordinate(binary()) -> {binary(), binary()}.
ec_point_to_coordinate(<<16#04, X:32/binary, Y:32/binary>>) ->
  {X, Y};
ec_point_to_coordinate(<<16#04, X:48/binary, Y:32/binary>>) ->
  {X, Y};
ec_point_to_coordinate(<<16#04, X:66/binary, Y:66/binary>>) ->
  {X, Y}.

-spec ec_coordinate_to_point(binary(), binary()) -> binary().
ec_coordinate_to_point(X, Y) ->
  <<16#04, X/binary, Y/binary>>.

-spec get_ec_curve(term()) -> secp256r1 | secp384r1 | secp521r1.
get_ec_curve(#'ECPoint'{point = <<16#04, _:32/binary, _:32/binary>>}) ->
  secp256r1;
get_ec_curve(#'ECPoint'{point = <<16#04, _:48/binary, _:48/binary>>}) ->
  secp384r1;
get_ec_curve(#'ECPoint'{point = <<16#04, _:66/binary, _:66/binary>>}) ->
 secp521r1.
