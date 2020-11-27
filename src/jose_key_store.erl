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

-module(jose_key_store).

-include_lib("kernel/include/logger.hrl").

-behaviour(gen_server).

-export([start_link/2,
         init/1,
         terminate/2,
         handle_call/3,
         handle_cast/2,
         handle_info/2]).

-export([add/3,
         remove/2,
         select/2]).

-type options() :: map().

-type gen_server_name() :: {local, term()}
                         | {global, term()}
                         | {via, atom(), term()}.

-type gen_server_ref() :: term()
                        | {term(), atom()}
                        | {global, term()}
                        | {via, atom(), term()}
                        | pid().

-type key_id() :: binary().

-spec add(gen_server_ref(), key_id(), public_key:public_key()) -> ok.
add(Ref, KId, PubKey) ->
    gen_server:call(Ref, {add, KId, PubKey}).

-spec remove(gen_server_ref(), key_id()) -> ok.
remove(Ref, KId) ->
    gen_server:call(Ref, {remove, KId}).

-spec select(gen_server_ref(), key_id()) -> {ok, public_key:public_key()} | error.
select(Ref, KId) ->
    gen_server:call(Ref, {select, KId}).

-spec start_link(gen_server_name(), options()) -> Result when
      Result :: {ok, pid()} | ignore | {error, term()}.
start_link(Name, Options) ->
    gen_server:start_link(Name, ?MODULE, [Options], []).

init([Options]) ->
    Tab = ets:new(certificate, [set, private]),
    _Filesnames = maps:get(files, Options, []),
    % TODO: populate db
    {ok, #{db => Tab}}.

terminate(_Reason, #{db := Tab}) ->
    ets:delete(Tab),
    ok.

handle_call({add, Kid, Key}, _From, #{db := Tab} = State) ->
    {reply, ok, State};

handle_call({remove, KId}, _From, #{db := Tab} = State) ->
    true = ets:delete(Tab, KId),
    {reply, ok, State};

handle_call({select, KId}, _From, #{db := Tab} = State) ->
    Response = case ets:lookup(Tab, KId) of
                   [{_Id, PubKey}] -> {ok, PubKey};
                   _Else -> error
               end,
    {reply, Response, State};

handle_call(Msg, From, State) ->
  ?LOG_WARNING("unhandled call ~p from ~p", [Msg, From]),
  {noreply, State}.

handle_cast(Msg, State) ->
  ?LOG_WARNING("unhandled cast ~p", [Msg]),
  {noreply, State}.

handle_info(Msg, State) ->
  ?LOG_WARNING("unhandled info ~p", [Msg]),
  {noreply, State}.
