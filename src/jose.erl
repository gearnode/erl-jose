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

-module(jose).

-export_type([header/0,
              header_parameter_name/0,
              kid/0,
              certificate_thumbprint/0,
              typ/0,
              cty/0]).

-type header() :: #{alg => jose_jwa:alg(),
                    jku => uri:uri(),
                    jwk => jose_jwk:jwk(),
                    kid => kid(),
                    x5u => uri:uri(),
                    x5c => [{'Certificate' | 'OTPCertificate', _, _, _}],
                    x5t => certificate_thumbprint(),
                    'x5t#S256' => certificate_thumbprint(),
                    typ => typ(),
                    cty => cty(),
                    b64 => boolean(),
                    crit => [header_parameter_name()]}.

-type header_parameter_name() :: binary().
-type kid() :: binary().
-type certificate_thumbprint() :: binary().
-type typ() :: binary().
-type cty() :: binary().
