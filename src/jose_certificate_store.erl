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

-module(jose_certificate_store).

-include_lib("kernel/include/logger.hrl").

-behaviour(gen_server).

-export([start_link/2,
         init/1,
         terminate/2,
         handle_call/3, handle_cast/2, handle_info/2]).

-export([add/2,
         remove/2,
         find/2]).

-type options() :: #{files => [file:name_all()]}.

-type state() :: #{db := ets:tab()}.

-spec add(et_gen_server:ref(), public_key:der_encoded()) ->
        ok.
add(Ref, Der) ->
  gen_server:call(Ref, {add, Der}, infinity).

-spec remove(et_gen_server:ref(), jose:certificate_thumbprint()) ->
        ok.
remove(Ref, Der) ->
  gen_server:call(Ref, {remove, Der}, infinity).

-spec find(et_gen_server:ref(), term()) ->
        {ok, jose:certificate()} | error.
find(Ref, Thumbprint) when byte_size(Thumbprint) =:= 20 ->
  gen_server:call(Ref, {find, {sha1, Thumbprint}}, infinity);
find(Ref, Thumbprint) when byte_size(Thumbprint) =:= 32 ->
  gen_server:call(Ref, {find, {sha2, Thumbprint}}, infinity);
find(Ref, {Sha, Thumbprint}) when Sha =:= sha1; Sha =:= sha2 ->
  gen_server:call(Ref, {find, {Sha, Thumbprint}}, infinity);
find(Ref, Cert) ->
  Der = public_key:pkix_encode('OTPCertificate', Cert, otp),
  Sha1 = crypto:hash(sha, Der),
  case find(Ref, Sha1) of
    {ok, Cert} ->
      {ok, Cert};
    error ->
      Sha2 = crypto:hash(sha256, Der),
      find(Ref, Sha2)
  end.

-spec start_link(et_gen_server:name(), options()) ->
        et_gen_server:start_ret().
start_link(Name, Options) ->
  gen_server:start_link(Name, ?MODULE, [Options], []).

-spec init(list()) -> et_gen_server:init_ret(state()).
init([Options]) ->
  Tab = ets:new(certificate, [set, private]),
  Filenames = maps:get(files, Options, []),
  Files = read_cert_files(Filenames, []),
  Certs = decode_cert_files(Files, []),
  lists:foreach(fun (Der) -> insert(Tab, Der) end, Certs),
  {ok, #{db => Tab}}.

-spec terminate(et_gen_server:terminate_reason(), state()) -> ok.
terminate(_Reason, #{db := Tab}) ->
  ets:delete(Tab),
  ok.

-spec handle_call(term(), {pid(), et_gen_server:request_id()}, state()) ->
        et_gen_server:handle_call_ret(state()).
handle_call({add, Der}, _From, State = #{db := Tab}) ->
  insert(Tab, Der),
  {reply, ok, State};

handle_call({remove, Der}, _From, State = #{db := Tab}) ->
  delete(Tab, Der),
  {reply, ok, State};

handle_call({find, Thumbprint}, _From, State = #{db := Tab}) ->
  case lookup(Tab, Thumbprint) of
    {ok, Cert} ->
      {reply, {ok, Cert}, State};
    error ->
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

-spec insert(ets:tid(), public_key:der_encoded()) ->
        no_return().
insert(Tab, Der) ->
  Cert = public_key:pkix_decode_cert(Der, otp),
  Sha1 = crypto:hash(sha, Der),
  Sha2 = crypto:hash(sha256, Der),
  true = ets:insert(Tab, {{sha1, Sha1}, Cert}),
  true = ets:insert(Tab, {{sha2, Sha2}, Cert}).

-spec delete(ets:tid(), public_key:der_encoded()) ->
        no_return().
delete(Tab, Der) ->
    Sha1 = crypto:hash(sha, Der),
    Sha2 = crypto:hash(sha256, Der),
    true = ets:delete(Tab, {sha1, Sha1}),
    true = ets:delete(Tab, {sha2, Sha2}).

-spec lookup(ets:tid(), Thumbprint :: binary()) ->
        {ok, jose:certificate()} | error.
lookup(Tab, Thumbprint) ->
  case ets:lookup(Tab, Thumbprint) of
    [{_, Cert}] -> {ok, Cert};
    _Else -> error
  end.

-spec read_cert_files([file:filename_all()], [binary()]) ->
        [binary()].
read_cert_files([], Acc) ->
  Acc;
read_cert_files([Filename | T], Acc) ->
  case file:read_file(Filename) of
    {ok, Content} -> read_cert_files(T, [Content | Acc]);
    {error, Reason} -> erlang:error(Reason)
  end.

-spec decode_cert_files([binary()], [term()]) ->
        [term()].
decode_cert_files([], Acc) ->
  Acc;
decode_cert_files([Content | T], Acc) ->
  AppendFun =
    fun ({'Certificate', Der, not_encrypted}, A) -> [Der | A];
        (_, _) -> erlang:error(invalid_certificate_bundle)
    end,
  Acc2 = lists:foldl(AppendFun, Acc, public_key:pem_decode(Content)),
  decode_cert_files(T, Acc2).
