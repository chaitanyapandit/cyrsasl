%%%===================================================================
%%% @copyright (C) 2012, Erlang Solutions Ltd.
%%% @doc Module supporting various authentication mechanisms
%%% @end
%%%===================================================================
-module(escalus_auth).

%% Public APi
-export([auth_plain/2,
         auth_digest_md5/2,
         auth_sasl_anon/2,
         auth_sasl_external/2]).

%% Useful helpers for writing own mechanisms
-export([get_challenge/2, 
	 md5_digest_response/2,
	 response_value/10,
         wait_for_success/2]).

-include_lib("exml/include/exml.hrl").

-import(string, [ tokens/2 ]).
-define(STR(Format, Args), lists:flatten(io_lib:format(Format, Args))).

%%--------------------------------------------------------------------
%% Public API
%%--------------------------------------------------------------------

auth_plain(Conn, Props) ->
    Username = get_property(username, Props),
    Password = get_property(password, Props),
    Payload = <<0:8,Username/binary,0:8,Password/binary>>,
    Stanza = escalus_stanza:auth_stanza(<<"PLAIN">>, base64_cdata(Payload)),
    ok = escalus_connection:send(Conn, Stanza),
    wait_for_success(Username, Conn).

auth_digest_md5(Conn, Props) ->
    ok = escalus_connection:send(Conn, escalus_stanza:auth_stanza(<<"DIGEST-MD5">>, [])),
    ChallengeData = get_challenge(Conn, challenge1),
    Response = md5_digest_response(ChallengeData, Props),
    ResponseStanza1 = escalus_stanza:auth_response_stanza([Response]),
    ok = escalus_connection:send(Conn, ResponseStanza1),
    [{<<"rspauth">>, _}] = get_challenge(Conn, challenge2), %% TODO: validate
    ResponseStanza2 = escalus_stanza:auth_response_stanza([]),
    ok = escalus_connection:send(Conn, ResponseStanza2),
    wait_for_success(get_property(username, Props), Conn).

auth_sasl_anon(Conn, Props) ->
    Stanza = escalus_stanza:auth_stanza(<<"ANONYMOUS">>, []),
    ok = escalus_connection:send(Conn, Stanza),
    wait_for_success(get_property(username, Props), Conn).

auth_sasl_external(Conn, Props) ->
    {server, ThisServer} = get_property(endpoint, Props),
    Stanza = escalus_stanza:auth_stanza(<<"EXTERNAL">>,
                                        [base64_cdata(ThisServer)]),
    ok = escalus_connection:send(Conn, Stanza),
    wait_for_success(ThisServer, Conn).


%%--------------------------------------------------------------------
%% Helpers - implementation
%%--------------------------------------------------------------------

md5_digest_response(ChallengeData, Props) ->
    %% Digest calculated via description at
    %% http://web.archive.org/web/20050224191820/http://cataclysm.cx/wip/digest-hex_md5-crash.html
    Username = get_property(username, Props),
    Password = get_property(password, Props),
    Server = get_property(server, Props),
    Resource = get_property(resource, Props),
    Nonce = get_property(<<"nonce">>, ChallengeData),
    CNonce = base16:encode(crypto:rand_bytes(16)),
    Realm = proplists:get_value(<<"realm">>, ChallengeData, <<>>),
    QOP = get_property(<<"qop">>, ChallengeData),
    NC = <<"00000001">>,
    ServType = <<"xmpp">>,
    DigestUri = <<"xmpp/", Server/binary>>,
    %io:format("~p:md5_digest_response Username is ~p",[?MODULE,Username]),
    FullJid = <<Username/binary, "@", Server/binary, "/", Resource/binary>>,

    Y = crypto:md5([Username, $:, Realm, $:, Password]),
    HA1 = hex_md5([Y, $:, Nonce, $:, CNonce, $:, FullJid]),
    HA2 = hex_md5([<<"AUTHENTICATE:">>, DigestUri]),

    %% Digest is the Z from the description above
    Digest = hex_md5([HA1, $:, Nonce, $:, NC, $:, CNonce, $:, QOP, $:, HA2]),

    A2Prefix = <<"AUTHENTICATE">>,
    DigestX = response_value(Username, Realm, Password, Nonce, CNonce, NC, QOP, A2Prefix, DigestUri, FullJid),

    DigestY = sasl_response(Username, Password, Realm, DigestUri, Nonce, CNonce, NC),

    R = base64_cdata(csvkv:format([
        {<<"username">>, Username},
	{<<"realm">>, Realm},
        {<<"nonce">>, Nonce},
        {<<"cnonce">>, CNonce},
        {<<"nc">>, NC},
        {<<"qop">>, QOP},
        %{<<"serv-type">>, ServType},
        %{<<"host">>, Server},
        {<<"digest-uri">>, DigestUri},
        {<<"response">>, DigestY}, %Digest}, %it_utils:atob(X) }, %Digest},
        {<<"charset">>, <<"utf-8">>}
        %,{<<"authzid">>, FullJid}
    ])),
    R.
    

hex_md5(Data) ->
    base16:encode(crypto:md5(Data)).

%%--------------------------------------------------------------------
%% Helpers - actions
%%--------------------------------------------------------------------

get_challenge(Conn, Descr) ->
    Challenge = escalus_connection:get_stanza(Conn, Descr),
    case Challenge of
        #xmlel{name = <<"challenge">>, children=[CData]} ->
            csvkv:parse(base64:decode(exml:unescape_cdata(CData)));
        _ ->
            throw({expected_challenge, got, Challenge})
    end.

wait_for_success(Username, Conn) ->
    AuthReply = escalus_connection:get_stanza(Conn, auth_reply),
    case AuthReply#xmlel.name of
        <<"success">> ->
            ok;
        <<"failure">> ->
            throw({auth_failed, Username, AuthReply})
    end.

get_property(PropName, Proplist) ->
    case lists:keyfind(PropName, 1, Proplist) of
        {PropName, Value} ->
            Value;
        false ->
            throw({missing_property, PropName})
    end.

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

base64_cdata(Payload) ->
    #xmlcdata{content=base64:encode(Payload)}.




%% == Functions defined in RFC2831 ==
%% These formats have the same names as specified in the mentioned RFC to make
%% it easier to understand and follow. For more information about the functions
%% look up the relevant sections in the RFC

response_value(Usr, Realm, Pwd, Nonce, Cnonce, Nc, Qop, A2Prefix, Duri, Azid) ->
    A1 = 'A1'(Usr, Realm, Pwd, Nonce, Cnonce, Azid),
    A2 = 'A2'(A2Prefix, Duri, Qop),
    K = 'HEX'('H'(A1)),
    S = [Nonce,":",Nc,":",Cnonce,":",Qop,":",'HEX'('H'(A2))],
    fl('HEX'('KD'(K,S))).

'H'(S) -> erlang:md5(fl(S)).

'KD'(K, S) -> 
    'H'([K,":",S]).

'HEX'(S) -> 
    [io_lib:format("~2.16.0b",[H]) || H <- binary_to_list(S)].

'A1'(Uname, Realm, Passwd, Nonce, Cnonce, undefined) ->
    ['H'([Uname,":",Realm,":",Passwd]),":",Nonce,":",Cnonce];
'A1'(Uname, Realm, Passwd, Nonce, Cnonce, Authzid) ->
    ['H'([Uname,":",Realm,":",Passwd]),":",Nonce,":",Cnonce,":",Authzid].

'A2'(Prefix, Duri, "auth") ->
    [Prefix,":",Duri];
'A2'(Prefix, Duri, _Other) -> 
    [Prefix,":",Duri,":00000000000000000000000000000000"].

%% flatten... but shorter. (yes, because I refuse to "import").
fl(L) -> lists:flatten(L).

%% https://github.com/daleharvey/erlang_util/blob/35246855afac30d6e35b679a842bfa3f71367b84/dh_jabber.erl
sasl_response(User, Pass, Realm, Uri, Nonce, CNonce, NC) ->
    A1 = crypto:md5(?STR("~s:~s:~s",[User, Realm, Pass])),
    A2 = md5_hex(?STR("AUTHENTICATE:~s",[Uri])),
    HA1 = md5_hex(?STR("~s:~s:~s",[A1,Nonce,CNonce])),
    md5_hex(?STR("~s:~s:~s:~s:auth:~s",[HA1,Nonce,NC,CNonce,A2])).

md5_hex(S) ->
       Md5_bin =  erlang:md5(S),
       Md5_list = binary_to_list(Md5_bin),
       lists:flatten(list_to_hex(Md5_list)).

list_to_hex(L) ->
       lists:map(fun(X) -> int_to_hex(X) end, L).
 
int_to_hex(N) when N < 256 ->
       [hex(N div 16), hex(N rem 16)].
 
hex(N) when N < 10 ->
       $0+N;
hex(N) when N >= 10, N < 16 ->
       $a + (N-10).
