# Authentication

Authentication is pluggable in wg-access-server. Community contributions are welcome
for supporting new authentication backends.

If you're just getting started you can skip over this section and rely on the default
admin account instead.

If your authentication system is not yet supported and you aren't quite ready to
contribute you could try using a project like [dex](https://github.com/dexidp/dex)
or SaaS provider like [Auth0](https://auth0.com/) which supports a wider variety of
authentication protocols. wg-access-server can happily be an OpenID Connect client
to a larger solution like this.

The following authentication backends are currently supported:

| Backend        | Use Case                                                                                      | Notes                                                               |
| -------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Simple Auth    | Deployments with a static list of users. Simple and great for self-hosters and home use-cases | Recommended, default for the admin account                          |
| Basic Auth     | Like Simple Auth, but using HTTP Basic Auth for login                                         | Logout does not work because browsers caches Basic Auth credentials |
| OpenID Connect | For delegating authentication to an existing identity solution                                |                                                                     |
| Gitlab         | For delegating authentication to gitlab. Supports self-hosted Gitlab.                         |                                                                     |

If `adminPassword` is set, an administrator account will be added with the username of `adminUsername` (default `admin`)
to the Simple Auth or Basic Auth backend; whichever is enabled, automatically enabling Simple if both are unset,
preferring Simple to Basic if both are enabled.

## Configuration

Currently authentication providers are only configurable via the wg-access-server
config file (config.yaml).

Below is an annotated example config section that can be used as a starting point.

```yaml
# You can disable the builtin admin account by leaving out 'adminPassword'. Requires another backend to be configured.
adminPassword: "<admin password>"
# adminUsername sets the user for the Basic/Simple Auth admin account if adminPassword is set.
# Every user of the basic and simple backend with a username matching adminUsername will have admin privileges.
adminUsername: "admin"
# Configure zero or more authentication backends
auth:
  sessionStore:
    # 32 random bytes in hexadecimal encoding (64 chars) used to sign session cookies. It's generated randomly
    # if not present. Need to be set when running in HA setup (more than one replica)
    secret: "<session store secret>"
    # How long a web session stays valid, as a duration such as "24h".
    # Defaults to 720h (30 days). The claims of a session - whether the user
    # is an admin and whether they still have access - are taken from the
    # identity provider at login and are not re-checked afterwards, and there
    # is no server-side session store to invalidate. This value is therefore
    # also how long it takes for access revoked at the provider to take
    # effect, so shorten it if that matters to you.
    maxAge: "720h"
    # Mark the session cookie as Secure so browsers only send it over HTTPS.
    # Defaults to false, because the web UI is also served over plain HTTP on
    # `port` - enabling this while users reach the UI over http:// silently
    # breaks login. Turn it on when the UI is only reachable via HTTPS.
    secure: false
  simple:
    # Users is a list of htpasswd encoded username:password pairs
    # supports BCrypt, Sha, Ssha, Md5
    # You can create a user using "htpasswd -nB <username>"
    users: []
  # HTTP Basic Authentication
  basic:
    # Users is a list of htpasswd encoded username:password pairs
    # supports BCrypt, Sha, Ssha, Md5
    # You can create a user using "htpasswd -nB <username>"
    users: []
  oidc:
    # A name for the backend (is shown on the login page and possibly in the devices list of the 'all devices' admin page)
    name: "My OIDC Backend"
    # Should point to the OIDC Issuer (excluding /.well-known/openid-configuration)
    issuer: "https://identity.example.com"
    # Your OIDC client credentials which would be provided by your OIDC provider
    clientID: "<client-id>"
    clientSecret: "<client-secret>"
    # The full redirect URL
    # The path can be almost anything as long as it doesn't
    # conflict with a path that the web UI uses.
    # /callback is recommended.
    redirectURL: "https://wg-access-server.example.com/callback"
    # List of scopes to request claims for. Must include 'openid'.
    # 'email' is added automatically when 'emailDomains' is used. Can include 'profile' to show the user's name in the UI.
    # Add custom ones if required for 'claimMapping'.
    # Defaults to ["openid"]
    scopes:
      - openid
      - profile
      - email
    # You can optionally restrict access to users with an email address
    # that matches an allowed domain. The comparison ignores case.
    # If empty or omitted then all email domains will be allowed.
    # Setting this adds the 'email' scope to the request if it is missing,
    # because the provider only sends the address when it was asked for.
    # A login is refused if the provider reports the address as unverified
    # ('email_verified: false'). Providers that say nothing about it are
    # accepted - the restriction is then only as good as whatever the
    # provider does about verification.
    emailDomains:
      - example.com
    # This is an advanced feature that allows you to define OIDC claim mapping expressions.
    # This feature is used to define wg-access-server admins based off a claim in your OIDC token.
    # A JSON-like object of claimKey: claimValue pairs as returned by the issuer is passed to the evaluation function.
    # See https://github.com/Knetic/govaluate/blob/9aa49832a739dcd78a5542ff189fb82c3e423116/MANUAL.md for the syntax.
    claimMapping:
      # This example works if you have a custom group_membership claim which is a list of strings
      admin: "'WireguardAdmins' in group_membership"
      access: "'WireguardAccess' in group_membership"
    # Let wg-access-server retrieve the claims from the ID Token instead of querying the UserInfo endpoint.
    # Some OIDC authorization provider implementations (e.g. ADFS) only publish claims in the ID Token.
    claimsFromIDToken: false
    # require this claim to be "true" to allow access for the user
    accessClaim: "access"
  gitlab:
    name: "My Gitlab Backend"
    baseURL: "https://mygitlab.example.com"
    clientID: "<client-id>"
    clientSecret: "<client-secret>"
    redirectURL: "https:///wg-access-server.example.com/callback"
    emailDomains:
      - example.com
```

## API tokens

With `enableApiTokens: true`, users can create tokens on the *API tokens* page of the web UI (the key
icon) and use the API from scripts without a browser session:

```sh
curl -H "Authorization: Bearer wgas_..." -H 'Content-Type: application/json' -d '{}' \
  https://wg-access-server.example.com/api/proto.Devices/ListDevices
```

A token acts as the user who created it and may do exactly what they may do in the web UI - an
admin's token has admin rights. It works for the API under `/api` only, not for the web UI.

- **What is stored:** only a SHA-256 hash of the token. The token itself is shown once, when it is
  created. Every token starts with `wgas_`, so a leaked one is easy to recognise, for secret scanners
  too.
- **Rights are checked on every request**, the way they are for a web session: a token carries the
  identity its owner had when creating it, and the server checks that identity against the current
  configuration. For Simple and Basic Auth, admin rights come from `adminUsername`, so a user who is
  no longer the configured admin loses them on their tokens too. For OIDC, a token is refused once
  the configuration requires an `accessClaim` its identity does not have.
- **Changes at the identity provider do not reach a token.** The claims of an OIDC user are those
  from the login the token was created in - just like a web session, only that a token can live
  longer. To take access away from somebody at once, delete the user in the web UI, which revokes
  their tokens, or revoke the tokens under *All tokens*.
- **Lifetime:** a token expires after 30 days, 90 days, a year or never, as chosen when creating it.
  Users can revoke their own tokens, admins every token (listed under *All tokens*). Deleting a user
  revokes their tokens too. A revoked or expired token stops working immediately, on every replica.
- **A token cannot create further tokens.** Otherwise a leaked token could outlive its expiry
  through the tokens it created. Creating a token needs a web session.

Requests with a token that does not work get a `401` (a disabled feature too), an owner who has lost
access a `403`. Creating and revoking tokens is recorded in the [audit log](./5-audit.md), and so is
which token made a change.

## Login throttling

Failed logins to the Simple Auth and Basic Auth backends are slowed down: after a wrong password the
next attempt for that username waits, and the wait doubles with every further failure, up to 10 seconds.
A successful login clears it, and a username that has not been tried for 15 minutes is forgotten.
Failed attempts are logged with the username and the remote address.

There is deliberately no lockout after N attempts: it would let anyone keep the admin account locked
simply by failing to log in on purpose. The counters are also kept per username rather than per client
address, because wg-access-server is commonly reached through a reverse proxy where every user shares
one address - and trusting `X-Forwarded-For` would let a client pick its own key and skip the throttle.

The counters live in the process, so in an HA setup every replica keeps its own. OIDC and GitLab logins
are handled by the identity provider and are not affected.

## OIDC Provider specifics

### Active Directory Federation Services (ADFS)

Please see [this helpful issue comment](https://github.com/freifunkMUC/wg-access-server/issues/213#issuecomment-1172656633) for instructions for ADFS 2016 and above.
