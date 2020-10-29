%% Copyright (c) 2020 Bryan Frimin <bryan@frimin.fr>.
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
%% REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
%% AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
%% INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
%% LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
%% OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
%% PERFORMANCE OF THIS SOFTWARE.

-module(jose_jws).

-export([produce_compact/4,
         produce_flattened_json/4,
         produce_flattened_json/5]).

-export_type([payload/0]).

-type payload() :: binary().

-spec produce_compact(jose:header(), payload(), jose_jwa:alg(), Key) -> binary() when
      Key :: jose_jwa:hmac_key() | jose_jwa:ecdsa_private_key().
produce_compact(Header, Payload, Alg, Key) ->
    EncodedHeader = jose_base:encode64url(json:serialize(Header, #{return_binary => true}), #{padding => false}),
    EncodedPayload = jose_base:encode64url(Payload, #{padding => false}),
    Message = <<EncodedHeader/binary, $., EncodedPayload/binary>>,
    Signature = jose_base:encode64url(jose_jwa:sign(Message, Alg, Key), #{padding => false}),
    <<Message/binary, $., Signature/binary>>.

-spec produce_flattened_json(jose:header(), payload(), jose_jwa:alg(), Key) -> binary() when
      Key :: jose_jwa:hmac_key() | jose_jwa:ecdsa_private_key().
produce_flattened_json(Header, Payload, Alg, Key) ->
    produce_flattened_json(Header, Payload, Alg, Key, [alg]).

-spec produce_flattened_json(jose:header(), payload(), jose_jwa:alg(), Key, [atom()]) -> binary() when
      Key :: jose_jwa:hmac_key() | jose_jwa:ecdsa_private_key().
produce_flattened_json(Header, Payload, Alg, Key, ProtectedHeaderKeys) ->
    EncodedPayload = jose_base:encode64url(Payload, #{padding => false}),
    SerializedHeader = json:serialize(Header, #{return_binary => true}),
    EncodedHeader = jose_base:encode64url(SerializedHeader, #{padding => false}),
    Signature = jose_jwa:sign(<<EncodedHeader/binary, $., EncodedPayload/binary>>, Alg, Key),
    EncodedSignature = jose_base:encode64url(Signature, #{return_binary => true}),
    ProtectedHeader = maps:with(ProtectedHeaderKeys, Header),
    SerializedProtectedHeader = json:serialize(ProtectedHeader, #{return_binary => true}),
    EncodedProtectedHeader = jose_base:encode64url(SerializedProtectedHeader, #{padding => false}),
    PublicHeader = maps:without(ProtectedHeaderKeys, Header),
    Message = #{signature => EncodedSignature, payload => EncodedPayload,
                header => PublicHeader, protected => EncodedProtectedHeader},
    json:serialize(Message, #{return_binary => true}).
