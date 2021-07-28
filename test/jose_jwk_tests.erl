%% Copyright (c) 2020, 2021 Bryan Frimin <bryan@frimin.fr>.
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

-module(jose_jwk_tests).

-include_lib("eunit/include/eunit.hrl").

decode_empty_json_object_test() ->
  ?assertEqual({error,{missing_parameter,kty}},
               jose_jwk:decode(<<"{}">>)).

decode_json_array_test() ->
  ?assertEqual({error, invalid_format},
               jose_jwk:decode(<<"[]">>)).

decode_empty_map_test() -> 
  ?assertEqual({error,{missing_parameter,kty}},
               jose_jwk:decode(#{})).

decode_term_test() ->
  ?assertEqual({error, invalid_format},
               jose_jwk:decode([])),
  ?assertEqual({error, invalid_format},
               jose_jwk:decode(foo)),
  ?assertEqual({error, invalid_format},
               jose_jwk:decode("hello")),
  ?assertEqual({error, invalid_format},
               jose_jwk:decode(1)).
  
decode_emtpy_bin_test() ->
  ?assertEqual({error,
                {invalid_format,
                 #{position => {1,1}, reason => no_value}}},
               jose_jwk:decode(<<>>)).

decode_jwk_with_not_supported_kty_test() ->
  ?assertEqual({error,
                {invalid_parameter,
                 {unsupported,<<"foobar">>}, kty}},
               jose_jwk:decode(#{<<"kty">> => <<"foobar">>})).

decode_rfc7520_3_1_test() ->
  {ok, File} = file:read_file("test/vectors/rfc7520_3_1.json"),
  ?assertEqual(
     {ok,
      #{crv => 'P-521',
        kid => <<"bilbo.baggins@hobbiton.example">>,
        kty => 'EC',
        use => sig,
        x =>
          <<0,114,153,44,179,172,8,236,243,229,198,61,237,236,
            13,81,168,193,247,158,242,248,47,148,243,199,55,
            191,93,231,152,102,113,234,198,37,254,130,87,187,
            208,57,70,68,202,170,58,175,143,39,164,88,95,187,
            202,208,242,69,118,32,8,94,92,143,66,173>>,
        y =>
          <<1,220,166,148,123,206,136,188,87,144,72,90,201,
            116,39,52,43,195,95,136,125,134,214,90,8,147,
            119,226,71,230,11,170,85,228,232,80,30,42,218,
            87,36,172,81,214,144,144,8,3,62,188,16,172,153,
            155,157,127,92,194,81,159,63,225,234,29,148,117>>}},
     jose_jwk:decode(File)).

decode_rfc7520_3_2_test() ->
  {ok, File} = file:read_file("test/vectors/rfc7520_3_2.json"),
  ?assertEqual(
     {ok,
      #{crv => 'P-521',
        d =>
          <<0,8,81,56,221,171,245,202,151,95,88,96,249,26,8,
            233,29,109,95,154,118,173,64,24,118,106,71,102,
            128,181,92,211,57,232,171,108,114,181,250,205,178,
            162,165,10,194,91,208,134,100,125,211,226,230,233,
            158,132,202,44,54,9,253,241,119,254,178,109>>,
        kid => <<"bilbo.baggins@hobbiton.example">>,
        kty => 'EC',
        use => sig,
        x =>
          <<0,114,153,44,179,172,8,236,243,229,198,61,237,236,
            13,81,168,193,247,158,242,248,47,148,243,199,55,
            191,93,231,152,102,113,234,198,37,254,130,87,187,
            208,57,70,68,202,170,58,175,143,39,164,88,95,187,
            202,208,242,69,118,32,8,94,92,143,66,173>>,
        y =>
          <<1,220,166,148,123,206,136,188,87,144,72,90,201,
            116,39,52,43,195,95,136,125,134,214,90,8,147,
            119,226,71,230,11,170,85,228,232,80,30,42,218,
            87,36,172,81,214,144,144,8,3,62,188,16,172,153,
            155,157,127,92,194,81,159,63,225,234,29,148,117>>}},
     jose_jwk:decode(File)).

rfc7520_3_1_match_rfc7520_3_2_test() ->
  {ok, File1} = file:read_file("test/vectors/rfc7520_3_1.json"),
  {ok, File2} = file:read_file("test/vectors/rfc7520_3_2.json"),
  
  {ok, #{x := X1, y := Y1}} = jose_jwk:decode(File1),
  {ok, #{x := X2, y := Y2}} = jose_jwk:decode(File2),

  ?assertEqual(X1, X2),
  ?assertEqual(Y1, Y2).

decode_rfc7520_3_3_test() ->
  {ok, File} = file:read_file("test/vectors/rfc7520_3_3.json"),
  ?assertEqual(
     {ok,
      #{e => 65537,
        kid => <<"bilbo.baggins@hobbiton.example">>,
        kty => 'RSA',
        n =>
          20135533008613362683983973718862990570890949482783547491074937566048838943004157274484500282679051238967930814182837332509745335321694730867914487474360313056717004122048241683576190451001206594369003880452220552186311851010130037332999299892700953157894377718386086768938058299374235398748350321163975673243254998238224668780038242796491971359194173117243083075284176788910883569789455869367283514387223800602948314723218768921623931105285092074647944930960873919066358313244754717122611255711161319444897038896496343014060976689972635082113758993979473481511550731351324005908071126862383299605264835961097030990287,
        use => sig}},
     jose_jwk:decode(File)).

decode_rfc7520_3_4_test() ->
  {ok, File} = file:read_file("test/vectors/rfc7520_3_4.json"),
  ?assertEqual(
     {ok,
      #{d =>
          13809785886921180797407749068700942981528089435771470964933339849531763931979658226246689941649114165877756904281400924998825599768673188627050679509247407590724566295036763464811978094688530662125180988122227281988347728446577123121956338123153675672384095849459356212372062261627372823030362241721140402534827920608159114397698659666564432536888691574732214992533122683199444713216582417478411683595580959548347164585150169575401765252679902902625147728179779840007171037544685861186766305472768461620252400817122383292377247352244817836750259386865218586191336825522033117854784997616980884291365145982447543137217,
        dp =>
          5452754506240497308759433019323719585992094222860760795439270374399299463296556858507586681668276080205271813815413736836746282351411023590382002932611213604063854267637328669893708400136364221707380683009522939987478513612504889192694812845812469959990700860994002219137017021229395442602718050574418216489,
        dq =>
          6103034953475782159405883067387392346274709877813314428160871698478072108156934906636939392429995910283894984471867749832357906395346648896814450690625379104589983172538233447538219918824119490007305320907809395266022012480039103665056876141436971569684073061958920103517814199063615863387684736238234656863,
        e => 65537,
        kid => <<"bilbo.baggins@hobbiton.example">>,
        kty => 'RSA',
        n =>
          20135533008613362683983973718862990570890949482783547491074937566048838943004157274484500282679051238967930814182837332509745335321694730867914487474360313056717004122048241683576190451001206594369003880452220552186311851010130037332999299892700953157894377718386086768938058299374235398748350321163975673243254998238224668780038242796491971359194173117243083075284176788910883569789455869367283514387223800602948314723218768921623931105285092074647944930960873919066358313244754717122611255711161319444897038896496343014060976689972635082113758993979473481511550731351324005908071126862383299605264835961097030990287,
        p =>
          155305159528675998315587554014523516083078608902053750652196202749677048642358299363759977556059891120561885641903854876605754500853726315968216134808579359395711784936178882676585818087673577574114127693348589707935410407050296794012012146664933439273320539907415872853360575628122941817407358922423140657993,
        q =>
          129651410614568017951696388521026752738348674639303464401419464668770635900253174384526773731502315063946718183900420330879494363511129117909409612613133053606973655487402983938837056343590378935691659259752059752852280269661044647292328198275965901381648329420292300429253481090448036576608977166562458575959,
        qi =>
          155171362656114787674005338316026300971092335901511555016027916093530558354739494408751451514346305783601055276983183518496184496218932854791325892306914322459078533545141895619742270863660955772717492371592287055310307433879513025000807527757356866299049054535097378049521944951691464480088870568286553270414,
        use => sig}},
     jose_jwk:decode(File)).

rfc7520_3_3_match_rfc7520_3_4_test() ->
  {ok, File1} = file:read_file("test/vectors/rfc7520_3_3.json"),
  {ok, File2} = file:read_file("test/vectors/rfc7520_3_4.json"),
  
  {ok, #{e := E1, n := N1}} = jose_jwk:decode(File1),
  {ok, #{e := E2, n := N2}} = jose_jwk:decode(File2),

  ?assertEqual(E1, E2),
  ?assertEqual(N1, N2).

decode_rfc7520_3_5_test() ->
  {ok, File} = file:read_file("test/vectors/rfc7520_3_5.json"),
  ?assertEqual(
     {ok,
      #{alg => hs256,
        k =>
          <<132,155,87,33,157,174,72,222,100,109,7,219,181,51,
            86,110,151,102,134,69,124,20,145,190,58,118,220,
            234,108,66,113,136>>,
        kid => <<"018c0ae5-4d9b-471b-bfd6-eef314bc7037">>,
        kty => oct,
        use => sig}},
     jose_jwk:decode(File)).
