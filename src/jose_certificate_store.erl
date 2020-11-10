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

-export([start_link/2,
         init/1,
         terminate/2,
         handle_call/3,
         handle_cast/2,
         handle_info/2]).

-export([add/2,
         remove/2,
         is_trusted/2]).

-type gen_server_name() :: {local, term()}
                         | {global, term()}
                         | {via, atom(), term()}.

-type options() :: map().

-type gen_server_ref() :: term()
                        | {term(), atom()}
                        | {global, term()}
                        | {via, atom(), term()}
                        | pid().

-spec start_link(gen_server_name(), options()) -> Result when
      Result :: {ok, pid()} | ignore | {error, term()}.
start_link(Name, Options) ->
    gen_server:start_link(Name, ?MODULE, [Options], []).

init([Options]) ->
    State = ets:new(certificate, []),
    % TODO: populate the state with options
    {ok, State}.

terminate(_Reason, Tab) ->
    ets:delete(Tab),
    ok.

-spec add(gen_server_ref(), jose:certificate()) -> ok.
add(Ref, Certificate) ->
    gen_server:call(Ref, {add, Certificate}).

-spec remove(gen_server_ref(), jose:certificate()) -> ok.
remove(Ref, Certificate) ->
    gen_server:call(Ref, {remove, Certificate}).

-spec is_trusted(gen_server_ref(), jose:certificate()) -> boolean().
is_trusted(Ref, Certificate) ->
    gen_server:call(Ref, {is_trusted, Certificate}).

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

handle_call({is_trusted, Certificate}, _From, Tab) ->
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
