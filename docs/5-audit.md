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
| `user.delete`   | An admin deleted a user, their devices and tokens  | `target_user`                  |
| `api_token.create` | An API token was created                        | `token`, `token_name`, `expires_at` |
| `api_token.delete` | An API token was revoked                        | `token`, `token_name`, `owner` |

\* `reason=inactive` marks a device the server deleted by itself because it exceeded the inactive
device grace period.

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
login attempt is logged with a warning (see [Authentication](./4-auth.md)).
