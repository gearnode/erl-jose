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

-export([encode_compact/4, decode_compact/3]).

-export_type([payload/0,
              compact/0,
              decode_error_reason/0]).

-type payload() :: binary().
-type compact() :: binary().
-type decode_error_reason() :: term()
                             | invalid_format
                             | {invalid_header, term()}
                             | {invalid_payload, term()}
                             | {invalid_signature, term()}.

-spec encode_compact(jose:header(), payload(), jose_jwa:alg(), jose_jwa:sign_key())->
          compact().
encode_compact(Header, Payload, Alg, Key) ->
    EncodedHeader = jose_base64:encode(json:serialize(Header, #{return_binary => true})),
    EncodedPayload = jose_base64:encode(Payload),
    Message = <<EncodedHeader/binary, $., EncodedPayload/binary>>,
    Signature = jose_base64:encode(jose_jwa:sign(Message, Alg, Key)),
    <<Message/binary, $., Signature/binary>>.

-spec decode_compact(compact(), jose_jwa:alg(), jose_jwa:verify_key()) ->
          {ok, payload()} | {error, decode_error_reason()}.
decode_compact(Token, Alg, Key) ->
    try
        case binary:split(Token, <<$.>>, [global]) of
            [EncHeader, EncPayload, EncSig] ->
                Header = decode_header(EncHeader),
                Payload = decode_payload(EncPayload),
                Signature = decode_signature(EncSig);
            _ ->
                {error, invalid_format}
        end
    catch
        thow:{error, Reason} ->
            {error, Reason}
    end.

-spec decode_header(binary()) -> jose:header().
decode_header(Data) ->
    case jose_base64:decode(Data) of
        {ok, Header} ->
            parse_header_object(Header);
        {error, Reason} ->
            throw({error, {invalid_header, Reason}})
    end.

-spec parse_header_object(binary()) -> jose:header().
parse_header_object(Data) ->
    case json:parse(Data, #{duplicate_key_handling => error}) of
        {ok, Header} ->
            parse_header_parameter_names(Header);
        {error, Reason} ->
            throw({error, {invalid_header, Reason}})
    end.

-spec parse_header_parameter_names(map()) -> jose:header().
parse_header_parameter_names(Header) ->
    maps:fold(fun parse_header_parameter_name/3, #{}, Header).

-spec parse_header_parameter_name(json:key(), json:value(), jose:header()) ->
          #{json:key() => term()}.
parse_header_parameter_name(<<"alg">>, Value, Header) ->
    case jose_jwa:support(Value) of
        true ->
            Header#{alg => Value};
        false ->
            throw({error, {invalid_header, {alg, unsupported_alg}}})
    end;
parse_header_parameter_name(<<"jku">>, Value, Header) ->
    case uri:parse(Value) of
        {ok, URI} ->
            Header#{jku => URI};
        {error, Reason} ->
            throw({error, {invalid_header, {jku, Reason}}})
    end;
parse_header_parameter_name(<<"kid">>, Value, Header) ->
    Header#{kid => Value};
parse_header_parameter_name(<<"x5u">>, Value, Header) ->
    case uri:parse(Value) of
        {ok, URI} ->
            Header#{x5u => URI};
        {error, Reason} ->
            throw({error, {invalid_header, {x5u, Reason}}})
    end;
%% parse_header_parameter_name(<<"x5c">>, [H | T], Header) ->
parse_header_parameter_name(<<"x5t">>, Value, Header) ->
    case jose_base64:decode(Value) of
        {ok, Thumbprint} ->
            Header#{x5t => Thumbprint};
        {error, Reason} ->
            throw({error, {invalid_header, {x5t, Reason}}})
    end;
parse_header_parameter_name(<<"x5t#S256">>, Value, Header) ->
    case jose_base64:decode(Value) of
        {ok, Thumbprint} ->
            Header#{'x5t#S256' => Thumbprint};
        {error, Reason} ->
            throw({error, {invalid_header, {'x5t#S256', Reason}}})
    end;
parse_header_parameter_name(<<"typ">>, Value, Header) ->
    Header#{typ => Value};
parse_header_parameter_name(<<"cty">>, Value, Header) ->
    Header#{cty => Value};
parse_header_parameter_name(<<"crit">>, [], Header) ->
    throw({error, {invalid_header, {crit, invalid_format}}});
parse_header_parameter_name(<<"crit">>, Value, Header) when is_list(Value) ->
    F = fun (X) when is_binary(X) -> X;
            (_) -> throw({error, {invalid_header, {crit, invalid_format}}})
        end,
    Header#{crit => lists:map(F, Value)};
parse_header_parameter_name(<<"crit">>, _Value, _Header) ->
    throw({error, {invalid_header, {crit, invalid_format}}});
parse_header_parameter_name(Key, Value, Header) ->
    Header#{Key => Value}.

-spec decode_payload(binary()) -> binary().
decode_payload(Data) ->
    case jose_base64:decode(Data) of
        {ok, Payload} ->
            Payload;
        {error, Reason} ->
            throw({error, {invalid_payload, Reason}})
    end.

-spec decode_signature(binary()) -> binary().
decode_signature(Data) ->
    case jose_base64:decode(Data) of
        {ok, Signature} ->
            Signature;
        {error, Reason} ->
            throw({error, {invalid_signature, Reason}})
    end.
