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
| GitHub         | Signing in with a GitHub account, restricted to organizations, teams or users. Supports GitHub Enterprise Server. | Needs an OAuth app, see [GitHub](#github) |

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
    # Every identity provider needs a name of its own, and none may be called "basic" or "simple":
    # the name tells the users of different providers apart, so the server refuses to start otherwise.
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
    # 'email' is added automatically when 'emailDomains' is used.
    # 'profile' is what makes the provider send a name or a username: without
    # it the UI lists everybody by their subject, the opaque identifier the
    # provider issues. The name is taken from the 'name' claim, falling back
    # to 'preferred_username', 'nickname' and 'given_name' - Keycloak only
    # fills 'name' for users who have a first and a last name.
    # Add custom ones if required for 'claimMapping'.
    # Defaults to ["openid", "profile"]
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
    # See https://github.com/casbin/govaluate/blob/master/MANUAL.md for the syntax.
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
  github:
    # Shown on the sign-in button. Defaults to "GitHub".
    name: "GitHub"
    clientID: "<client-id>"
    clientSecret: "<client-secret>"
    # Must match the callback URL of the OAuth app. Use a path of its own
    # if another provider already uses /callback.
    redirectURL: "https://wg-access-server.example.com/callback/github"
    # Only for GitHub Enterprise Server; leave out for github.com.
    # baseURL: "https://github.example.com"
    # Who may sign in - at least one of these is required, because anybody
    # can create a GitHub account. A user who matches any of them gets in.
    organizations:
      - my-org
    teams:
      - my-org/vpn-users
    users:
      - octocat
    # Who is an admin.
    adminTeams:
      - my-org/vpn-admins
    adminUsers: []
```

## Access policies

Which networks somebody's devices may reach can depend on who they are. The networks are configured
under `vpn.policies` (see [Configuration](./configuration.md)), and a rule per policy decides who is
in it:

```yaml
auth:
  oidc:
    # ... issuer, clientID and the rest as above
    policyMapping:
      # the same claims and the same syntax as claimMapping, one rule per policy
      contractors: "'Contractors' in group_membership"
      staff: "'Staff' in group_membership"
```

Every rule that comes out `true` puts the person in that policy, so they can be in several - a rule
per policy is why, where `claimMapping` can only give one value to a name. Only `true` counts: a
rule that returns a string does not name a policy, or a claim of the provider could decide which
networks somebody reaches.

Which policies somebody is in is worked out at their sign-in and remembered until the next one - the
server has no way to ask the provider in between. A group that is taken away therefore takes effect
when they sign in again, as an admin right does today.

Somebody in no policy, and everybody signing in through basic or simple auth, keeps `vpn.allowedIPs`.

The admin page shows which policies somebody ended up in, which is how a rule is checked against
what the provider actually sends.

## Changing your password

With `basic` or `simple` auth the password comes from the config file, which only an admin can edit.
Somebody signed in that way can now set their own instead, under the key icon in the navigation:

- The **config file stays the list of who may sign in.** A password is only ever stored for a user it
  lists, so a stored password can never create an account.
- What they set is kept as a bcrypt hash in the `users` table, together with the configured entry it
  was set against. While that entry is unchanged, their password is the one that counts and the
  configured one stops working.
- **An admin editing the entry in the config file takes it back**: the stored password was set
  against an entry that is no longer there, so it is ignored and the configured password counts
  again. That is how a password is reset - there is no other way in, by design.
- Changing it **ends every other session** of that person. Whoever knew the old password may be
  holding one.
- It is stored as **bcrypt**, which salts every hash itself: the salt is part of the stored string,
  so the same password set by two people does not look the same, and one precomputed set of hashes
  cannot be tried against the whole table. The configured entries are whatever an admin wrote -
  `htpasswd` also writes unsalted SHA-1 (`{SHA}`), which is why `htpasswd -nB` (bcrypt) is the one
  to use there.
- A password set here has to be at least 10 characters. The configured entries are not held to that:
  those are an admin's business, and refusing them at sign-in would lock people out.
- **Five wrong passwords** - here, when turning the second factor off or when replacing the recovery
  codes - stop the password from being checked for 15 minutes after the last wrong one. A stolen
  session must not be a way to guess the password. Only somebody signed in as the person can use
  them up, and signing in is not affected.

Their devices are unaffected either way - a tunnel does not use anybody's password.

With an identity provider there is nothing here to change: the password is theirs, and the page says
so rather than pretending otherwise.

## Passkeys

A passkey is a credential the browser holds - in a laptop's own authenticator, on a phone, on a
security key - and it is the better second factor, because it is bound to this site. A page
pretending to be this one cannot ask for it, and there is nothing a person can be talked into reading
out over the telephone. Somebody signing in with `simple` auth can register one under the key icon,
as many as they like: one to carry, one in a drawer.

- A credential id that is already registered is refused, whoever is asking. An authenticator picks
  its own credential ids, so without that rule somebody could register the id of another person's
  passkey and take their second factor away.
- It is asked for **after the password**, like a code. Which of the two a person uses is up to them;
  the sign-in page offers both when both are set up.
- Removing the last one hands the account back to the password alone, and the question says so.
- **A passkey can be renamed.** The name is the person's own label, and a drawer key that moved to a
  keyring should not have to be registered again to say so. Only the name changes: the credential
  and the sign count stay as they are, so a renamed passkey signs its owner in exactly as before.
- The credential itself never leaves the browser. The server keeps the public half, the name the
  person gave it, and how often it has been used - the count is what gives a cloned authenticator
  away.

!!! note

    **Passkeys need HTTPS.** No browser will make or use one on a page served over plain `http://`,
    localhost aside - that is the WebAuthn specification, not a choice made here. Serve the web UI
    over TLS, or behind a proxy that does; the page says so rather than offering a button that
    cannot work.

Which host the passkey is bound to comes from `vpn.externalHost`. Behind a reverse proxy that is the
name people type, which is what it has to be: the `Host` header is whatever reached the server. With
no `externalHost` configured, the request's host is used instead, and the server says so at startup:
a passkey registered under one name is not offered under another, so whoever registers one through a
second name - or through a proxy that passes a different `Host` on - ends up with a credential the
sign-in page will not ask for.

## Two-factor authentication

Somebody signing in with `simple` auth can ask for a code from an authenticator app on top of their
password, under the same key icon. It works anywhere, including over plain HTTP, which is why it is
here beside the passkeys. It is TOTP - RFC 6238, six digits, thirty seconds - so every
authenticator app does it, and the server checks the step before and after the current one, because
phones and servers rarely agree on the second.

- **Setting it up asks for a code before it counts.** Until that code arrives, the secret is stored
  but nothing is asked of anybody: a QR code somebody walked away from locks nobody out.
- **A code signs in once.** It is good for the current thirty second step and the one either side,
  so that phones and servers need not agree on the second, but the step it was accepted at is
  remembered and nothing up to that step is taken again (RFC 6238 §5.2).
- **Ten recovery codes** come with it, shown once. Each signs in once and is used up by it. Only
  their hashes are kept, so nothing here can show them again - and they are hashed with SHA-256
  rather than bcrypt, because they are long random strings and ten slow hashes per attempt would be
  a way to hold the server up.
- **A fresh set can be asked for at any time**, under the same key icon, and it asks for the
  password for the same reason turning it off does. The old codes stop working the moment the new
  ones are made. The authenticator app is not touched - the shared secret stays, so nothing has to
  be scanned again, and a code that has just signed somebody in stays used up. It is recorded as
  `user.recovery_codes`, with how many were left beforehand and never the codes themselves.
- **Turning it off asks for the password**, so that a browser left signed in is not enough to take
  it away.
- **An admin can remove it** for somebody whose phone is gone, from the user list under _admin_.
  Their password alone then signs them in again, so it is as much trust as handing out a password -
  and it is recorded as `user.two_factor_reset`.

The password step and the code step are two requests. Between them the browser holds a cookie that
says whose password was right and expires after five minutes; it is not a login, and nothing reads
an identity out of it. A code posted without that step sends the browser back to the sign-in page.

The secret is stored as the authenticator app needs it - a shared secret cannot be hashed, or
neither side could compute the same code. It is worth the same care as the device keys in the same
database.

!!! note

    This is for `simple` auth, the sign-in page. `basic` auth is the browser's own username and
    password dialog, which has nowhere to ask for a second one: it refuses an account that has a
    second factor rather than letting the password alone sign it in, and nobody signed in with it
    can set one up. With an identity provider, the second factor belongs there.

## Sessions

Signing in creates a session, and the cookie the browser gets carries **nothing but its id**. Who
signed in, and what their identity provider said about them, is kept by the server.

That is what makes a session something the server can end:

- **Signing out** ends it, rather than only dropping the cookie. A cookie that was copied elsewhere
  stops working with it.
- **Deleting a user** ends every session they have, along with their devices and their API tokens.
- It takes effect **everywhere at once**: a session is read from the storage on every request, so
  there is nothing to tell the other replicas.

A session lasts as long as `auth.sessionStore.maxAge` (30 days by default) and is removed once it
has expired. Along with it the server keeps what the browser said about itself and the address it
came from, so that somebody can tell their own sessions apart; the id itself is stored only as a
hash, so whoever reads the database learns which sessions exist, not how to use them.

!!! note

    **Upgrading signs everybody out once.** Their cookies carry an identity, which this version no
    longer reads - it wants a session id, and there is none. They sign in again and are on the new
    scheme.

### Where you are signed in

The shield in the navigation lists every browser that is signed in as you: what it said it was,
the address it came from, when it signed in and when it was last used. The one asking is marked
**This browser**.

- **Sign out** on a row ends that one session, at once and everywhere. Do that for a session you do
  not recognise, or for a computer you left signed in somewhere.
- **Sign out everywhere else** ends all of them but the one you are looking at, which is the thing
  to reach for after a password went through the wrong hands.

Everybody manages their own sessions; there is no admin view of somebody else's. Taking another
person's access away is a different job, and it takes their devices and their API tokens with it:
that is what [Revoke access](https://github.com/freifunkMUC/wg-access-server#taking-somebodys-access-away)
in the admin user list does.

What this does *not* do: end a tunnel. A device keeps connecting whether or not anybody is signed
in - that is what [blocking a device](../#device-access) is for. A session is the web UI and the
API: adding devices, downloading their configuration, and whatever else the person may do.

## What the server remembers about a sign-in

A sign-in writes a row: the identifier the provider uses for the person, which provider it was, their
display name and email address as the provider reports them, and the time. It is replaced at every
sign-in, so it always describes the last one.

The server needs this because almost everything it does happens while nobody is signed in. The
device list, the DNS zone and the firewall rules are built by a background job or after a restart,
and until now the only thing it knew about a person outside their session was the owner of a device.
It is also what the access policies will be built on: which groups somebody is in is something only
their identity provider knows, and only at the moment they sign in.

Two things follow from it:

- The admin page shows when somebody last signed in, and it lists people who have signed in but have
  not added a device yet.
- Deleting a user removes that row along with their devices and their API tokens.

Name and email address were already stored with every device, so nothing is kept that was not kept
before - except for a person who has no device at all.

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
access a `403`. Creating and revoking tokens is recorded in the [audit log](./audit.md), and so is
which token made a change.

## GitHub

GitHub does not offer OpenID Connect for signing in users, so it has a backend of its own rather than
an `oidc` configuration.

1. Create an OAuth app: for a personal account under *Settings → Developer settings → OAuth Apps*,
   for an organization under *Organization settings → Developer settings → OAuth Apps*.
2. Set the *Authorization callback URL* to your `redirectURL`, e.g.
   `https://wg-access-server.example.com/callback/github`.
3. Put the client ID and a client secret into the `github` section and restrict who may sign in with
   `organizations`, `teams` or `users`. The server refuses to start without any of them: anybody can
   create a GitHub account, and every one of them could otherwise add VPN devices.

Some things worth knowing:

- **Organizations and teams** are checked with the `read:org` scope, which is only requested when
  they are configured. Only an *active* membership counts, a pending invitation does not. If the
  organization restricts third-party access, an owner has to approve the OAuth app first - until then
  GitHub does not show the memberships to it, and signing in fails.
- **Users** are matched by their login, ignoring case. A GitHub user can rename their account, and
  somebody else can then register the old login. Prefer organizations or teams where you can.
- **Devices belong to the GitHub account id**, not the login, so they stay with the account across
  a rename. Accounts of a GitHub Enterprise Server are kept apart from github.com ones.
- The primary email address is shown in the web UI if GitHub verified it.
- As with every provider, membership is checked when signing in. Removing somebody from the
  organization takes effect when their web session ends (`sessionStore.maxAge`). Deleting the user in
  the web UI removes their devices and API tokens at once, but not a session they still have.

## Login throttling

Failed logins to the Simple Auth and Basic Auth backends are slowed down: after a wrong password the
next attempt for that username waits, and the wait doubles with every further failure, up to 10 seconds.
A successful login clears it, and a username that has not been tried for 15 minutes is forgotten.
Failed attempts are logged with the username and the remote address.

The second step is different: after 10 wrong codes or passkeys it is refused for 15 minutes after the
last wrong one, and the right password does not give the attempts back. A delay alone is not enough
there, because six digits are only a million guesses and parallel requests all wait at once. Only
somebody who knows the password can use up these attempts, so the limit cannot lock anybody else out.

Usernames longer than 256 bytes are refused without being counted or logged.

There is deliberately no lockout after N wrong passwords: it would let anyone keep the admin account
locked simply by failing to log in on purpose. The counters are also kept per username rather than per client
address, because wg-access-server is commonly reached through a reverse proxy where every user shares
one address - and trusting `X-Forwarded-For` would let a client pick its own key and skip the throttle.

The counters live in the process, so in an HA setup every replica keeps its own. OIDC and GitLab logins
are handled by the identity provider and are not affected.

## OIDC Provider specifics

### Active Directory Federation Services (ADFS)

Please see [this helpful issue comment](https://github.com/freifunkMUC/wg-access-server/issues/213#issuecomment-1172656633) for instructions for ADFS 2016 and above.
