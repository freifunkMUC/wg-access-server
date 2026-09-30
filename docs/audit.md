# Audit Log

wg-access-server records the changes that matter for an operator in its normal log output, so they
end up wherever the rest of the logs go. Every such record carries an `audit` field with the action,
which is what you filter on:

```
level=info msg=device.delete audit=device.delete actor=admin actor_is_admin=true actor_provider=simple \
  component=audit device=laptop owner=alice remote_addr=198.51.100.7 trace.id=…
```

## Recorded actions

| Action          | When                                              | Fields beside the actor        |
| --------------- | ------------------------------------------------- | ------------------------------ |
| `device.create` | A device was added                                 | `device`, `owner`, `address`   |
| `device.delete` | A device was deleted                               | `device`, `owner`, `reason`\*  |
| `device.rename` | A device was renamed                               | `device`, `previous`, `owner`  |
| `device.access` | An admin blocked a device or changed its expiry     | `device`, `owner`, `disabled`, `expires_at`\*\* |
| `device.expire` | A device lost its access because its expiry passed | `device`, `owner`              |
| `device.routes` | An admin changed the networks behind a device       | `device`, `owner`, `routes`    |
| `device.rotate` | Somebody gave their device a new key                | `device`, `owner`              |
| `user.delete`   | An admin deleted a user, their devices and tokens  | `target_user`                  |
| `user.revoke`   | An admin took somebody's access away               | `target_user`, `devices_blocked`, `tokens_deleted`, `sessions_ended` |
| `user.password` | Somebody changed their own password                | `sessions_ended`               |
| `user.two_factor` | Somebody turned their own second factor on or off | `enabled`                    |
| `user.two_factor_reset` | An admin removed somebody's second factor  | `target_user`                  |
| `user.passkey_add` | Somebody registered a passkey of their own     | `passkey` (its name)           |
| `user.passkey_delete` | Somebody removed a passkey of their own     | `passkey` (its id)             |
| `session.delete` | Somebody ended a browser session of theirs        | `session`, or `sessions` and `reason`\*\*\* |
| `api_token.create` | An API token was created                        | `token`, `token_name`, `expires_at` |
| `api_token.delete` | An API token was revoked                        | `token`, `token_name`, `owner` |

\* `reason=inactive` marks a device the server deleted by itself because it exceeded the inactive
device grace period.

\*\* The record says what the device's access looks like after the change, not what was changed.
`expires_at` is absent when the device's access does not expire.

\*\*\* `session` names the one session that was ended. "Sign out everywhere else" ends several at
once and records `sessions` as how many that was, with `reason=all others`; the ids are not worth a
record each, they are gone.

`user.two_factor` and `user.two_factor_reset` record that it happened, never the secret, a code or
a recovery code.

`user.password` records that the password changed and how many other sessions that ended. Neither
the old nor the new password is recorded, in any form.

`device.rotate` records that the key changed, not the keys: the new public key says nothing an
operator needs, and key material does not belong in a log.

`device.expire` is recorded by the server itself, so its actor is `system`: nobody asked for it, the
date an admin set earlier simply passed. It is recorded once per device, when the peer is removed.

## Who did it

| Field            | Meaning                                                                              |
| ---------------- | ------------------------------------------------------------------------------------ |
| `actor`          | The user that made the change, or `system` for changes wg-access-server made on its own |
| `actor_provider` | The authentication backend that user logged in with                                    |
| `actor_is_admin` | Whether the actor acted with admin rights                                              |
| `actor_api_token`| The id of the API token the change was made with; absent for the web UI               |
| `owner`          | The user the affected device belongs to - different from `actor` means an admin acted on somebody else's device |
| `remote_addr`    | The address the request came from. Behind a reverse proxy this is the proxy           |
| `trace.id`       | Ties the record to the other log lines of the same request                            |

Only successful changes are recorded: an action that was refused or failed leaves no record, it is
logged as an error instead. Reads - listing devices or users - are not recorded, the web UI polls them
constantly and the records would drown everything else.

Logins are logged separately: a new session is logged with the provider and the user, and a failed
login attempt is logged with a warning (see [Authentication](./auth.md)).
