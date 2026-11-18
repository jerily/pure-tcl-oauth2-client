# SPDX-License-Identifier: MIT
package require pure-tcl-oauth2-core 0.1.0
namespace eval ::oauth2::client {
    namespace import ::oauth2::core::*
    variable transfers
}
# A bounded transport. No redirects, automatic retries, cookies or verbose output.
proc ::oauth2::client::http_data {id bytes handle} {
    variable transfers
    if {[string length $transfers($id,body)] + [string length $bytes] > 1048576} {
        set transfers($id,large) 1
        $handle cancel
        return
    }
    append transfers($id,body) $bytes
}
proc ::oauth2::client::http_done {id handle} {variable transfers; set transfers($id,done) 1}
proc ::oauth2::client::http {method url fields headers} {
    package require trequests 1.3.0
    variable transfers
    set id [::oauth2::core::random 12]
    set transfers($id,body) {}; set transfers($id,large) 0; set transfers($id,done) 0
    set options [list -headers $headers -verify true -allow_redirects false -timeout 15000 -timeout_connect 5000 \
        -async -buffer_response false -callback_data [list ::oauth2::client::http_data $id] -callback [list ::oauth2::client::http_done $id]]
    if {$method eq "POST"} {lappend options -content_type application/x-www-form-urlencoded -data [::oauth2::core::form_encode $fields]}
    set handle {}
    try {
        set handle [::trequests::request $method $url {*}$options]
        if {!$transfers($id,done)} {vwait ::oauth2::client::transfers($id,done)}
        if {$transfers($id,large) || [$handle state] eq "error"} {::oauth2::core::fail temporarily_unavailable "Provider request failed"}
        set responseHeaders {}
        foreach name {content-type cache-control etag} {
            if {![catch {$handle header $name} values]} {dict set responseHeaders $name [join $values {, }]}
        }
        dict create status [expr {[$handle status_code]}] headers $responseHeaders body $transfers($id,body)
    } finally {
        if {$handle ne {}} {$handle destroy}
        array unset transfers $id,*
    }
}
oo::class create ::oauth2::client::Client {
    variable config store metadata metadataUntil jwks jwksUntil lastKeyRefresh
    constructor {args} {
        set config [::oauth2::core::options {
            -provider {} -issuer {} -client_id {} -client_secret {} -redirect_uri {}
            -scopes {openid email profile} -auth_method client_secret_post -transaction_store {}
            -aead {} -allow_http false -transport ::oauth2::client::http -clock {clock seconds}
            -metadata {} -transaction_ttl 600 -algorithms RS256 -clock_skew 60
        } {*}$args]
        if {[dict get $config -provider] ni {{} google}} {error "Unsupported provider profile"}
        if {[dict get $config -provider] eq "google"} {
            if {[dict get $config -issuer] ni {{} https://accounts.google.com}} {error "Invalid Google issuer"}
            dict set config -issuer https://accounts.google.com
        }
        foreach key {-issuer -redirect_uri} {::oauth2::core::url [dict get $config $key] [dict get $config -allow_http]}
        if {[string first ? [dict get $config -issuer]] >= 0} {error "Issuer must not contain a query"}
        foreach key {-client_id -transaction_store} {if {[dict get $config $key] eq {}} {error "$key is required"}}
        if {[dict get $config -auth_method] ni {client_secret_post client_secret_basic none}} {error "Unsupported token authentication"}
        if {[dict get $config -auth_method] ne "none" && [dict get $config -client_secret] eq {}} {error "Client secret is required"}
        ::oauth2::core::integer [dict get $config -transaction_ttl] 30 1800
        ::oauth2::core::integer [dict get $config -clock_skew] 0 300
        ::oauth2::core::scopes [join [dict get $config -scopes] { }]
        foreach alg [dict get $config -algorithms] {if {$alg ni {RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512}} {error "Unsupported OIDC signing algorithm"}}
        set store [dict get $config -transaction_store]
        if {[$store durable] && [dict get $config -aead] eq {}} {error "Durable client transactions require an AEAD handle"}
        set metadata {}; set metadataUntil 0; set jwks {}; set jwksUntil 0; set lastKeyRefresh -1000000
    }
    method now {} {{*}[dict get $config -clock]}
    method request {method url fields {headers {}}} {
        ::oauth2::core::url $url [dict get $config -allow_http]
        if {[catch {{*}[dict get $config -transport] $method $url $fields $headers} result]} {::oauth2::core::fail temporarily_unavailable "Provider request failed"}
        if {![dict exists $result status] || ![dict exists $result body] || [string length [dict get $result body]] > 1048576} {::oauth2::core::fail invalid_response "Invalid provider response"}
        if {![dict exists $result headers]} {dict set result headers {}}
        return $result
    }
    method document {url} {
        set response [my request GET $url {} {Accept application/json}]
        if {[dict get $response status] != 200} {::oauth2::core::fail temporarily_unavailable "Provider metadata unavailable"}
        dict set response fields [::oauth2::core::json_bytes [dict get $response body]]
        return $response
    }
    method metadata {} {
        if {$metadata ne {} && $metadataUntil > [my now]} {return $metadata}
        set configured [dict get $config -metadata]
        if {$configured ne {}} {set fields [::oauth2::core::json $configured]} else {
            set fields [dict get [my document [string trimright [dict get $config -issuer] /]/.well-known/openid-configuration] fields]
        }
        if {[::oauth2::core::claim_string $fields issuer] ne [dict get $config -issuer]} {::oauth2::core::fail invalid_response "Discovery issuer mismatch"}
        foreach name {authorization_endpoint token_endpoint} {
            ::oauth2::core::url [::oauth2::core::claim_string $fields $name] [dict get $config -allow_http]
        }
        foreach name {jwks_uri userinfo_endpoint revocation_endpoint introspection_endpoint} {
            if {[dict exists $fields $name]} {::oauth2::core::url [::oauth2::core::claim_string $fields $name] [dict get $config -allow_http]}
        }
        if {[dict exists $fields code_challenge_methods_supported] && {S S256} ni [::oauth2::core::value $fields code_challenge_methods_supported L]} {
            ::oauth2::core::fail invalid_response "Provider does not support S256 PKCE"
        }
        set metadata $fields; set metadataUntil [expr {[my now]+3600}]
        return $metadata
    }
    method start {args} {
        set opts [::oauth2::core::options {-browser_session {} -return_to / -prompt {}} {*}$args]
        set browser [dict get $opts -browser_session]
        if {$browser eq {}} {::oauth2::core::fail invalid_request "Browser session is required"}
        set returnTo [::oauth2::core::return_path [dict get $opts -return_to]]
        set metadata [my metadata]
        set state [::oauth2::core::random]; set nonce [::oauth2::core::random]
        set pkce [::oauth2::core::pkce]
        set fields [dict create response_type code client_id [dict get $config -client_id] redirect_uri [dict get $config -redirect_uri] \
            scope [join [dict get $config -scopes] { }] state $state code_challenge [dict get $pkce code_challenge] code_challenge_method S256]
        set oidc [expr {"openid" in [dict get $config -scopes]}]
        if {$oidc} {dict set fields nonce $nonce}
        if {[dict get $opts -prompt] ne {}} {
            if {[dict get $opts -prompt] ni {none login consent select_account}} {::oauth2::core::fail invalid_request "Unsupported prompt"}
            dict set fields prompt [dict get $opts -prompt]
        }
        set payload [dict create verifier [dict get $pkce code_verifier] nonce $nonce return_to $returnTo \
            issuer [dict get $config -issuer] client_id [dict get $config -client_id] redirect_uri [dict get $config -redirect_uri] oidc $oidc]
        set id [::oauth2::core::digest $state]
        set browser [::oauth2::core::digest $browser]
        set record [dict create browser $browser sealed false payload $payload]
        if {[dict get $config -aead] ne {}} {
            dict set record sealed true
            dict set record payload [binary encode base64 -maxlen 0 [::tink::aead::encrypt [dict get $config -aead] \
                [encoding convertto utf-8 $payload] [encoding convertto utf-8 [list oauth2-transaction $id $browser]]]]
        }
        $store put client_transaction $id $record [expr {[my now]+[dict get $config -transaction_ttl]}]
        dict create authorization_url [::oauth2::core::query_url [::oauth2::core::claim_string $metadata authorization_endpoint] $fields] state $state
    }
    method consume {state browser} {
        set id [::oauth2::core::digest $state]
        set record [$store get client_transaction $id [my now]]
        if {$record eq {} || ![::oauth2::core::equal [dict get $record data browser] [::oauth2::core::digest $browser]]} {::oauth2::core::fail invalid_state "Invalid or expired login transaction"}
        if {![$store delete client_transaction $id $record]} {::oauth2::core::fail invalid_state "Login transaction was already consumed"}
        set payload [dict get $record data payload]
        if {[dict get $record data sealed]} {
            if {[catch {encoding convertfrom -profile strict utf-8 [::tink::aead::decrypt [dict get $config -aead] \
                [binary decode base64 -strict $payload] [encoding convertto utf-8 [list oauth2-transaction $id [dict get $record data browser]]]]} payload]} {
                ::oauth2::core::fail invalid_state "Invalid login transaction"
            }
        }
        foreach name {issuer client_id redirect_uri} {
            if {[dict get $payload $name] ne [dict get $config -$name]} {::oauth2::core::fail invalid_state "Login configuration changed"}
        }
        return $payload
    }
    method authenticated_request {url fields} {
        set headers {Accept application/json}
        switch [dict get $config -auth_method] {
            client_secret_basic {
                set credentials [::oauth2::core::percent [dict get $config -client_id]]:[::oauth2::core::percent [dict get $config -client_secret]]
                dict set headers Authorization "Basic [binary encode base64 -maxlen 0 [encoding convertto ascii $credentials]]"
            }
            client_secret_post {dict set fields client_id [dict get $config -client_id]; dict set fields client_secret [dict get $config -client_secret]}
            none {dict set fields client_id [dict get $config -client_id]}
        }
        my request POST $url $fields $headers
    }
    method token {fields} {
        set meta [my metadata]
        set response [my authenticated_request [::oauth2::core::claim_string $meta token_endpoint] $fields]
        if {[dict get $response status] != 200} {::oauth2::core::fail invalid_grant "Provider rejected the token request"}
        set json [::oauth2::core::json_bytes [dict get $response body]]
        if {[dict exists $json error]} {::oauth2::core::fail invalid_grant "Provider rejected the token request"}
        set token [::oauth2::core::claim_string $json access_token]
        if {[string tolower [::oauth2::core::claim_string $json token_type]] ne "bearer"} {::oauth2::core::fail invalid_response "Unsupported token type"}
        set lifetime [::oauth2::core::integer [::oauth2::core::value $json expires_in N] 1 31536000]
        set scope [::oauth2::core::claim_string $json scope [join [dict get $config -scopes] { }]]
        if {[dict get $config -provider] eq "google"} {
            set scope [join [lmap item [split $scope { }] {
                switch $item {
                    https://www.googleapis.com/auth/userinfo.email {set item email}
                    https://www.googleapis.com/auth/userinfo.profile {set item profile}
                }
                set item
            }] { }]
        }
        ::oauth2::core::scope_subset $scope [join [dict get $config -scopes] { }]
        dict create access_token $token token_type Bearer expires_at [expr {[my now]+$lifetime}] scope $scope \
            refresh_token [::oauth2::core::claim_string $json refresh_token {}] id_token [::oauth2::core::claim_string $json id_token {}]
    }
    method keys {{force false}} {
        set now [my now]
        if {!$force && $jwks ne {} && $jwksUntil > $now} {return $jwks}
        if {$force && $lastKeyRefresh + 30 > $now} {return $jwks}
        set lastKeyRefresh $now
        set response [my document [::oauth2::core::claim_string [my metadata] jwks_uri]]
        set keys [dict get $response fields]
        set entries [::oauth2::core::value $keys keys L]
        if {[llength $entries] < 1 || [llength $entries] > 100} {::oauth2::core::fail invalid_response "Invalid JWKS size"}
        set lifetime 300
        if {[dict exists $response headers cache-control] && [regexp -nocase {max-age=([0-9]+)} [dict get $response headers cache-control] -> maxage]} {set lifetime [expr {min(86400,$maxage)}]}
        set jwks $keys; set jwksUntil [expr {$now+$lifetime}]
        return $jwks
    }
    method identity {tokens nonce} {
        set token [dict get $tokens id_token]
        if {$token eq {}} {::oauth2::core::fail invalid_token "ID token is required"}
        set parts [::oauth2::core::jwt_parts $token [dict get $config -algorithms]]
        set kid [::oauth2::core::claim_string [dict get $parts header] kid {}]
        set alg [dict get $parts alg]
        set keys [my keys]
        if {[catch {::oauth2::core::jwks_key $keys $kid $alg} key opts]} {
            if {[dict get $opts -errorcode] ne {OAUTH2 unknown_key}} {return -options $opts $key}
            set key [::oauth2::core::jwks_key [my keys true] $kid $alg]
        }
        set issuers [list [dict get $config -issuer]]
        if {[dict get $config -provider] eq "google"} {lappend issuers accounts.google.com}
        try {
            set claims [::oauth2::core::jwt_verify $key $token -algorithms [dict get $config -algorithms] -issuer $issuers \
                -audience [dict get $config -client_id] -nonce $nonce -access_token [dict get $tokens access_token] \
                -now [my now] -skew [dict get $config -clock_skew]]
        } finally {::tink::unregister_keyset $key}
        dict set tokens claims $claims
        dict set tokens issuer [dict get $config -issuer]
        dict set tokens subject [::oauth2::core::claim_string $claims sub]
        return $tokens
    }
    method callback {parameters args} {
        set opts [::oauth2::core::options {-browser_session {}} {*}$args]
        if {![dict exists $parameters state] || [dict get $opts -browser_session] eq {}} {::oauth2::core::fail invalid_state "Login transaction is required"}
        set payload [$store atomic [list [self] consume [dict get $parameters state] [dict get $opts -browser_session]]]
        set meta [my metadata]
        set requireIssuer [::oauth2::core::value $meta authorization_response_iss_parameter_supported BOOL false]
        if {($requireIssuer && ![dict exists $parameters iss]) || ([dict exists $parameters iss] && [dict get $parameters iss] ne [dict get $config -issuer])} {::oauth2::core::fail invalid_state "Authorization issuer mismatch"}
        if {[dict exists $parameters error]} {::oauth2::core::fail access_denied "Provider authorization was not completed"}
        if {![dict exists $parameters code] || [dict get $parameters code] eq {} || [string length [dict get $parameters code]] > 4096} {::oauth2::core::fail invalid_request "Authorization code is required"}
        set tokens [my token [dict create grant_type authorization_code code [dict get $parameters code] redirect_uri [dict get $payload redirect_uri] code_verifier [dict get $payload verifier]]]
        if {[dict get $payload oidc]} {set tokens [my identity $tokens [dict get $payload nonce]]}
        dict set tokens return_to [dict get $payload return_to]
        return $tokens
    }
    method refresh {tokens} {
        if {![dict exists $tokens refresh_token] || [dict get $tokens refresh_token] eq {}} {::oauth2::core::fail invalid_grant "No refresh token"}
        set fresh [my token [dict create grant_type refresh_token refresh_token [dict get $tokens refresh_token]]]
        ::oauth2::core::scope_subset [dict get $fresh scope] [dict get $tokens scope]
        if {[dict get $fresh refresh_token] eq {}} {dict set fresh refresh_token [dict get $tokens refresh_token]}
        if {[dict get $fresh id_token] ne {}} {
            set fresh [my identity $fresh {}]
            if {![dict exists $tokens subject] || [dict get $fresh subject] ne [dict get $tokens subject]} {::oauth2::core::fail invalid_token "Refreshed subject changed"}
            if {[dict exists $fresh claims nonce] && (![dict exists $tokens claims nonce] || [dict get $fresh claims nonce] ne [dict get $tokens claims nonce])} {
                ::oauth2::core::fail invalid_token "Refreshed nonce changed"
            }
        } else {foreach name {subject issuer claims} {if {[dict exists $tokens $name]} {dict set fresh $name [dict get $tokens $name]}}}
        return $fresh
    }
    method userinfo {tokens} {
        set response [my request GET [::oauth2::core::claim_string [my metadata] userinfo_endpoint] {} [dict create Authorization "Bearer [dict get $tokens access_token]" Accept application/json]]
        if {[dict get $response status] != 200} {::oauth2::core::fail invalid_response "UserInfo request failed"}
        set claims [::oauth2::core::json_bytes [dict get $response body]]
        if {![dict exists $tokens subject] || [::oauth2::core::claim_string $claims sub] ne [dict get $tokens subject]} {::oauth2::core::fail invalid_token "UserInfo subject mismatch"}
        return $claims
    }
    method revoke {token} {
        set response [my authenticated_request [::oauth2::core::claim_string [my metadata] revocation_endpoint] [dict create token $token]]
        if {[dict get $response status] != 200} {::oauth2::core::fail invalid_response "Revocation failed"}
    }
    method introspect {token} {
        set response [my authenticated_request [::oauth2::core::claim_string [my metadata] introspection_endpoint] [dict create token $token]]
        if {[dict get $response status] != 200} {::oauth2::core::fail invalid_response "Introspection failed"}
        ::oauth2::core::json_bytes [dict get $response body]
    }
}
proc ::oauth2::client::create {args} {::oauth2::client::Client new {*}$args}
foreach method {start callback refresh userinfo revoke introspect} {
    proc ::oauth2::client::$method {client args} [format {tailcall $client %s {*}$args} $method]
}
package provide pure-tcl-oauth2-client 0.1.0
