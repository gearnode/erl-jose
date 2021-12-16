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

-module(jose_trusted_store).

-include_lib("kernel/include/logger.hrl").

-behaviour(gen_server).

-export([start_link/2,
         init/1, terminate/2,
         handle_continue/2, handle_call/3, handle_cast/2]).

-type state() :: #{options := term(),
                   db := sqlite_database:ref()}.

start_link(Name, Options) ->
  gen_server:start_link(Name, ?MODULE, [Options], []).

-spec init(list()) -> et_gen_server:init_ret(state()).
init([Options]) ->
  try
    Ref = open_database(),
    State = #{db => Ref, options => Options},
    update_schema(State),
    {ok, State, {continue, import}}
  catch
    throw:{error, Reason} ->
      {stop, Reason}
  end.

-spec terminate(et_gen_server:terminate_reason(), state()) -> ok.
terminate(_, #{db := Ref}) ->
  sqlite:close(Ref),
  ok.

-spec handle_continue(term(), state()) ->
        et_gen_server:handle_continue_ret(state()).
handle_continue(import, #{options := Options} = State) ->
  %% TODO do import
  {noreply, State};

handle_continue(Msg, State) ->
  ?LOG_WARNING("unhandled call ~p", [Msg]),
  {noreply, State}.


handle_call(Msg, From, State) ->
  ?LOG_WARNING("unhandled call ~p from ~p", [Msg, From]),
  {reply, unhandled, State}.

-spec handle_cast(term(), state()) -> et_gen_server:handle_cast_ret(state()).
handle_cast(Msg, State) ->
  ?LOG_WARNING("unhandled cast ~p", [Msg]),
  {noreply, State}.

-spec open_database() -> sqlite_database:ref().
open_database() ->
  case sqlite:open(<<":memory:">>, #{}) of
    {ok, Ref} ->
      Ref;
    {error, Reason} ->
      throw({error, {open, Reason}})
  end.

-spec update_schema(state()) -> ok.
update_schema(State) ->
  Queries =
    [["PRAGMA foreign_keys = ON"],
     ["CREATE TABLE certificates",
      "  (sha BLOB NOT NULL,",
      "   sha256 BLOB NOT NULL,",
      "   der BLOB NOT NULL,",
      "   public_key_id BLOB,",
      "   FOREIGN KEY(public_key_id) REFERENCES public_keys(id))"],
     ["CREATE TABLE public_keys",
      "  (id BLOB PRIMARY KEY,",
      "   der BLOB NOT NULL)"]],
  lists:foreach(fun (Query) -> query(Query, [], State) end, Queries).

-spec query(sqlite:query(), [sqlite:parameter()], state()) -> [sqlite:row()].
query(Query, Parameters, #{db := Ref}) ->
  case sqlite:query(Ref, Query, Parameters) of
    {ok, Rows} ->
      Rows;
    {error, Reason} ->
      throw({error, {query, Reason, Query}})
  end.
