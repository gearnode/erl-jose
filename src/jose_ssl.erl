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

-module(jose_ssl).

-include_lib("public_key/include/public_key.hrl").

-export([verify_with_fingerprint/3]).

-export_type([fingerprint_state/0]).

-type cert() :: #'OTPCertificate'{}.
-type event() :: {bad_cert, Reason :: atom() | {revoked, atom()}}
               | {extension, #'Extension'{}}
               | valid
               | valid_peer.

-type user_state() :: term().
-type fingerprint_state() :: term().

-spec verify_with_fingerprint(cert(), event(), fingerprint_state()) ->
        {valid, user_state()}
          | {valid_peer, fingerprint_state()}
          | {fail, Reason :: term()}
          | {unknown, user_state()}.
verify_with_fingerprint(_, {extension, _}, UserState) ->
  {unknown, UserState};
verify_with_fingerprint(Cert, _, UserState) ->
  case proplists:get_value(check_fingerprint, UserState) of
    undefined ->
      {valid, UserState};
    {Algorithm, HexA} ->
      {Algorithm, HexA} = Fingerprint,
      case hex:decode(HexA) of
        {error, Reason} ->
          {fail, {invalid_fingerprint, Reason}};
        {ok, HexB} ->
          CertBin = public_key:pkix_encode('OTPCertificate', Cert, 'otp'),
          case crypto:hash(Algorithm, CertBin) of
            HexB ->
              {valid, hex:encode(HexB, [uppercase])};
            _ ->
              {fail, fingerprint_no_match}
          end
      end
  end.

