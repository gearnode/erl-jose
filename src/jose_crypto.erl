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

-module(jose_crypto).

-export([extract_pub_from_cert/1,
         extract_pub_from_chain/1]).

-export_type([]).

-include_lib("public_key/include/public_key.hrl").

-spec extract_pub_from_cert(term()) ->
        term().
extract_pub_from_cert(Cert) ->
  Cert#'OTPCertificate'.tbsCertificate
    #'OTPTBSCertificate'.subjectPublicKeyInfo
    #'OTPSubjectPublicKeyInfo'.subjectPublicKey.

-spec extract_pub_from_chain([term()]) ->
        term().
extract_pub_from_chain([]) ->
  none;
extract_pub_from_chain(Chain) ->
  [Root | _] = Chain,
  case public_key:pkix_path_validation(Root, Chain, []) of
    {ok, {PublicKeyInfo, _}} ->
      PublicKeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey;
    {error, _Reason} ->
      none
  end.
