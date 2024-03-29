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

-module(jose_sup).

-behaviour(supervisor).

-export([start_link/0, init/1]).

-spec start_link() -> supervisor:startlink_ret().
start_link() ->
  supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
  Children = [certificate_store_spec(), key_store_spec()],
  Flags = #{strategy => one_for_one, intensity => 1, period => 5},
  {ok, {Flags, Children}}.

-spec certificate_store_spec() ->
        supervisor:child_spec().
certificate_store_spec() ->
  Options = application:get_env(jose, certificate_store, #{}),
  #{id => certificate_store,
    start =>
      {jose_certificate_store, start_link,
       [{local, certificate_store_default}, Options]}}.

-spec key_store_spec() ->
        supervisor:child_spec().
key_store_spec() ->
  Options = application:get_env(jose, key_store, #{}),
  #{id => key_store,
    start =>
      {jose_key_store, start_link,
       [{local, key_store_default}, Options]}}.
