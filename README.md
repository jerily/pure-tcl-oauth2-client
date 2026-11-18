# pure-tcl-oauth2-client

OAuth2 authorization-code client with mandatory S256 PKCE, browser-bound state,
and OpenID Connect ID-token verification. Uses `pure-tcl-oauth2-core` for tjson
and Tink integration, and `trequests >=1.3.0` for HTTPS. No framework is required.

```tcl
package require pure-tcl-oauth2-client 0.1.0
set client [::oauth2::client::create -provider google \
    -client_id $clientId -client_secret $clientSecret \
    -redirect_uri https://app.example/login/google/callback \
    -transaction_store $sqlStore -aead $persistentAeadHandle]
set login [$client start -browser_session $sessionToken -return_to /account]
# Redirect to [dict get $login authorization_url].
set identity [$client callback $queryFields -browser_session $sessionToken]
# Only now use identity's issuer and subject to locate an application account.
$client destroy
```

The host issues a secure HttpOnly, SameSite=Lax browser cookie, checks CSRF/origin
on the login-start POST, parses the raw callback query with
`::oauth2::core::form_decode`, and rotates its application session after success.
Keep callback pages free of third-party resources and redirect to a clean URL.
Pass a stable browser session secret, not an IP, email or user-supplied identifier.

## Configuration and methods

Required options: `-issuer`, `-client_id`, `-redirect_uri`, `-transaction_store`.
`-provider google` supplies and pins Google's issuer. Other defaults:

| Option | Default / behavior |
| --- | --- |
| `-scopes` | Tcl list `{openid email profile}`; omit `openid` for plain OAuth2 |
| `-auth_method` | `client_secret_post`; also `client_secret_basic` or public-client `none` |
| `-client_secret` | Required for confidential clients; stays server-side |
| `-aead` | Required for durable storage; borrowed Tink AEAD handle |
| `-algorithms` | `RS256`; explicit RSA/PSS/EC allowlist, no `none` or HS OIDC |
| `-allow_http` | False; true permits only loopback HTTP |
| `-transaction_ttl` | 600 seconds, bounded 30–1800 |
| `-clock_skew` | 60 seconds, bounded 0–300 |
| `-clock` | `{clock seconds}` command prefix |
| `-transport` | `::oauth2::client::http` command prefix |
| `-metadata` | Optional trusted discovery JSON for offline tests or pinned deployments |

`start -browser_session token ?-return_to /? ?-prompt select_account?` returns
`authorization_url` and `state`. Transactions bind provider, client, redirect,
browser, nonce and PKCE verifier. A callback consumes state once, including error
responses; a failed exchange needs a new start. Return destinations are local paths.

`callback fields -browser_session token` returns `access_token`, `token_type`,
`expires_at`, `scope`, `refresh_token`, `id_token`, and `return_to`. OIDC adds
`issuer`, `subject` and typed `claims`. Plain OAuth2 does not authenticate a user.

`refresh tokens` rotates returned credentials, preserves an omitted refresh token,
and validates any replacement ID token, subject, nonce and scope.
`userinfo tokens` checks that the returned subject matches the verified ID token.
`revoke token` and `introspect token` use discovered endpoints when available.
Equivalent command wrappers exist, e.g. `::oauth2::client::callback $client ...`.
The caller owns token persistence; encrypt retained access/refresh tokens with
context-bound AEAD. A login-only application can discard them after verification.

Discovery is pinned to the configured issuer and cached for one hour. JWKS caches
honor `max-age` up to 24 hours (default five minutes). An unknown key triggers one
refresh, with a 30-second minimum between fetches. Failures never accept unsigned
or unverifiable tokens. Google accepts its documented bare or HTTPS issuer, maps
userinfo scope aliases, and exposes a single canonical issuer to the application.

The transport receives `method url formFields headers` and returns
`{status integer headers dictionary body utf8Bytes}`. It must implement verified
TLS, no redirects, no credential logging and bounded time/body size. The default
sets a 15-second timeout, five-second connect timeout and 1 MiB response limit.
It performs no automatic retry of token POSTs. Host infrastructure owns DNS/egress
policy for configured providers. Never construct provider endpoints from requests.

Run `tclsh9.1 tests/all.tcl` after installing the dependencies. See
`pure-tcl-oauth2-examples` for runnable local and Google flows.
