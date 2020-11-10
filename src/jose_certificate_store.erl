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

-module(jose_certificate_store).

-include_lib("kernel/include/logger.hrl").

-behaviour(gen_server).

-export([start_link/0,
         init/1,
         terminate/2,
         handle_call/3,
         handle_cast/2,
         handle_info/2]).

-export([add/1,
         remove/1,
         trusted/1]).

-spec start_link() -> Result when
      Result :: {ok, pid()} | ignore | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    State = ets:new(certificate, []),
    {ok, State}.

terminate(_Reason, Tab) ->
    ets:delete(Tab),
    ok.

-spec add(jose:certificate()) -> ok.
add(Certificate) ->
    gen_server:call(?MODULE, {add, Certificate}).

-spec remove(jose:certificate()) -> ok.
remove(Certificate) ->
    gen_server:call(?MODULE, {remove, Certificate}).

-spec trusted(jose:certificate()) -> boolean().
trusted(Certificate) ->
    gen_server:call(?MODULE, {trusted, Certificate}).

handle_call({add, Certificate}, _From, Tab) ->
    Fingerprint = certificate_fingerprint(Certificate),
    true = ets:insert(Tab, {Fingerprint}),
    ?LOG_INFO("add certificate ~p in the trusted certificate store", [Fingerprint]),
    {reply, ok, Tab};

handle_call({remove, Certificate}, _From, Tab) ->
    Fingerprint = certificate_fingerprint(Certificate),
    true = ets:delete(Tab, Fingerprint),
    ?LOG_INFO("remove certificate ~p in the trusted certificate store", [Fingerprint]),
    {reply, ok, Tab};

handle_call({trusted, Certificate}, _From, Tab) ->
    Fingerprint = certificate_fingerprint(Certificate),
    Result = ets:member(Tab, Fingerprint),
    {reply, Result, Tab};

handle_call(Msg, From, State) ->
  ?LOG_WARNING("unhandled call ~p from ~p", [Msg, From]),
  {noreply, State}.

handle_cast(Msg, State) ->
  ?LOG_WARNING("unhandled cast ~p", [Msg]),
  {noreply, State}.

handle_info(Msg, State) ->
  ?LOG_WARNING("unhandled info ~p", [Msg]),
  {noreply, State}.

certificate_fingerprint(Certificate) ->
    Der = public_key:pkix_encode('OTPCertificate', Certificate, otp),
    Hash = crypto:hash(sha256, Der),
    lists:flatten(string:join([io_lib:format("~2.16.0b",[C1]) || <<C1>> <= Hash], ":")).
