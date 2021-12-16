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

-module(jose_key_store).

-include_lib("kernel/include/logger.hrl").

-behaviour(gen_server).

-export([start_link/2,
         init/1,
         terminate/2,
         handle_call/3,
         handle_cast/2,
         handle_info/2]).

-export([add/2,
         remove/2,
         find/2]).

-type options() :: #{files => [file:name_all()]}.

-type state() :: #{db := ets:tab()}.

-type key_id() :: binary().

-spec add(et_gen_server:ref(), public_key:pem_entry()) ->
        ok | error.
add(Ref, PemEntry) ->
  gen_server:call(Ref, {add, PemEntry}, infinity).

-spec remove(et_gen_server:ref(), key_id()) ->
        ok.
remove(Ref, KId) ->
  gen_server:call(Ref, {remove, KId}, infinity).

-spec find(et_gen_server:ref(), key_id()) ->
        {ok, public_key:public_key()} | error.
find(Ref, KId) ->
  gen_server:call(Ref, {select, KId}, infinity).

-spec start_link(et_gen_server:name(), options()) ->
        et_gen_server:start_ret().
start_link(Name, Options) ->
  gen_server:start_link(Name, ?MODULE, [Options], []).

-spec init(list()) -> et_gen_server:init_ret(state()).
init([Options]) ->
  Tab = ets:new(certificate, [set, private]),
  Filenames = maps:get(files, Options, []),
  Files = read_key_files(Filenames, []),
  Keys = decode_key_files(Files, []),
  F = fun (X) ->
          case insert(Tab, X) of
            ok -> none;
            error -> erlang:error(invalid_public_key)
          end
      end,
  lists:foreach(F, Keys),
  {ok, #{db => Tab}}.

-spec terminate(et_gen_server:terminate_reason(), state()) -> ok.
terminate(_Reason, #{db := Tab}) ->
  ets:delete(Tab),
  ok.

-spec handle_call(term(), {pid(), et_gen_server:request_id()}, state()) ->
        et_gen_server:handle_call_ret(state()).
handle_call({add, PemEntry}, _From, #{db := Tab} = State) ->
  case insert(Tab, PemEntry) of
    ok -> {reply, ok, State};
    error -> {reply, error, State}
  end;

handle_call({remove, KId}, _From, #{db := Tab} = State) ->
  true = ets:delete(Tab, KId),
  {reply, ok, State};

handle_call({select, KId}, _From, #{db := Tab} = State) ->
  case ets:lookup(Tab, KId) of
    [{_Id, PubKey}] ->
      {reply, {ok, PubKey}, State};
    _Else ->
      {reply, error, State}
  end;

handle_call(Msg, From, State) ->
  ?LOG_WARNING("unhandled call ~p from ~p", [Msg, From]),
  {reply, unhandled, State}.

-spec handle_cast(term(), state()) ->
        et_gen_server:handle_cast_ret(state()).
handle_cast(Msg, State) ->
  ?LOG_WARNING("unhandled cast ~p", [Msg]),
  {noreply, State}.

-spec handle_info(term(), state()) ->
        et_gen_server:handle_info_ret(state()).
handle_info(Msg, State) ->
  ?LOG_WARNING("unhandled info ~p", [Msg]),
  {noreply, State}.

-spec insert(ets:tid(), public_key:pem_entry()) ->
        ok | error.
insert(Tab, {'SubjectPublicKeyInfo', Der, not_encrypted} = PE) ->
  case public_key:pem_entry_decode(PE) of
    {'RSAPublicKey', _, _} = PK ->
      KId = crypto:hash(md5, Der),
      true = ets:insert(Tab, {KId, PK}),
      ok;
    {{'ECPoint', _}, {namedCurve, _}} = PK ->
      KId = crypto:hash(md5, Der),
      true = ets:insert(Tab, {KId, PK}),
      ok;
    _Else ->
      error
  end;
insert(_, _) ->
  error.

-spec read_key_files([file:name_all()], [binary()]) ->
        [binary()].
read_key_files([], Acc) ->
  Acc;
read_key_files([Filename | T], Acc) ->
  case file:read_file(Filename) of
    {ok, Content} -> read_key_files(T, [Content | Acc]);
    {error, Reason} -> erlang:error(Reason)
  end.

-spec decode_key_files([binary()], [public_key:pem_entry()]) ->
        [public_key:pem_entry()].
decode_key_files([], Acc) ->
  Acc;
decode_key_files([Content | T], Acc0) ->
  F = fun
        ({'SubjectPublicKeyInfo', _, not_encrypted} = PE, A) ->
          [PE | A];
        (_, _) ->
          erlang:error(invalid_public_key)
      end,
  Acc = lists:foldl(F, Acc0, public_key:pem_decode(Content)),
  decode_key_files(T, Acc).
