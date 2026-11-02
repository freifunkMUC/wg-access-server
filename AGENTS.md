# AI Coding Assistants

This document is for AI tools, and for the people using them, when they contribute to
wg-access-server. It is adapted from the Linux kernel's
[AI Coding Assistants](https://docs.kernel.org/process/coding-assistants.html) guideline.

AI tools follow the same process as every other contribution:

- [README → Development](README.md#development) for the local setup and the tests,
- the style of the surrounding code, in Go and in TypeScript,
- the checks CI runs (see [Checks before a pull request](#checks-before-a-pull-request)).

Agents make mistakes that look like finished work: a test that passes without the fix, a default
stated from memory, a report of something that was not done. Everything below exists to catch them
before a maintainer has to.

## Licensing

wg-access-server is licensed under the [MIT License](LICENSE).

- Contributed code must be compatible with the MIT License.
- Do not copy code of unclear origin, or under a copyleft license such as the GPL, into the
  repository.
- New dependencies need a license compatible with MIT.

## Responsibility and attribution

An AI tool cannot take responsibility for a contribution. The person submitting it must:

- review and understand all AI-generated code,
- make sure it complies with the licensing requirements above,
- take full responsibility for the contribution.

Agents must not add `Signed-off-by` tags, and must not name themselves as an author: no
`Co-authored-by` for the AI, and none for a human on their behalf. Commits written with AI
assistance carry an `Assisted-by` trailer instead:

```text
Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]
```

`[TOOL1] [TOOL2]` are specialized analysis tools that were actually used, such as `govulncheck` or
`staticcheck`. Basic development tools - git, go, npm, editors, and the linters CI runs anyway - are
not listed. Example:

```text
Assisted-by: Claude Code:claude-opus-5-5 govulncheck
```

Say in the pull request description that AI assistance was used.

## Working with a maintainer

- **One topic per pull request, small enough to read.** A maintainer has to understand every line
  they merge. Several unrelated fixes, or a feature with its refactoring, are several pull requests.
- **Changes to authentication, sessions, API tokens, the second factor or the firewall** should be
  reviewed by a second person, not only by the one who asked the agent. Say so in the description.
- **Pushing, opening pull requests and anything else that leaves the machine** happens only when the
  person asked for it. Never push to `master`; work on a branch.
- **End with a report**: what was done, what was not, what could not be tested, and where the tests
  share the blind spots of the code they test - an agent writing both the fix and its test can make
  the same mistake twice.

## Repository rules

- **Start from the current `master`.** Run `git fetch` and compare `master` with `origin/master`
  before an audit or a branch. A stale checkout produces findings and fixes for code that no longer
  exists.
- **Look facts up instead of recalling them.** Library defaults, configuration defaults and what a
  function does are read from the code, not stated from memory.
- Commit messages follow Conventional Commits with a scope, as in the history: `fix(auth): …`,
  `feat(ui): …`, `docs: …`, `chore: …`. The body says what was wrong and why the change fixes it.
- Pull request descriptions are not empty: **what** changed, **why**, **how it was tested** and
  **what was not tested**.
- Do not edit generated code by hand. Change `proto/*.proto` and regenerate:
  - `proto/proto/` with `./codegen.sh`
  - `website/src/sdk/` with `cd website && npm run codegen`
- Keep `website/package.json` and `website/package-lock.json` in sync.
- **No secrets, keys or real user data**, in code, tests, logs or commit messages. Test data is
  synthetic. A made-up key that looks like a real one makes Gitleaks fail: use a value of low
  entropy, such as `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=` for a WireGuard key. Pull requests
  are squash-merged, so an entry in `.gitleaksignore` has to name the commit on `master`, which only
  exists after the merge.
- **No root on the developer's machine.** `sudo go run . serve` changes the host's network
  configuration (WireGuard interfaces, iptables or nftables). An agent does not run it, or anything
  else as root, without the developer's explicit confirmation. Use the tests, or
  `go run . serve --no-wireguard-enabled` as described in the README.

## Checks before a pull request

Run the checks that apply to the change. CI runs all of them:

```sh
go build ./...
go vet ./...
go test ./...
go test -race ./...                       # with WG_TEST_POSTGRES_URI and WG_TEST_MYSQL_URI, see the README
golangci-lint run                         # CI uses golangci-lint v2.13
typos                                     # uses .typos.toml
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
cd website && npm ci && npm run lint && npm test && npm run build
mkdocs build --strict                     # for changes under docs/, with requirements-docs.txt
```

A change must not add lint warnings or Typos findings. Typos also reads identifiers; a short name
that looks like a misspelling needs a better name or an entry in `.typos.toml`.

When a check could not be run locally, say which one in the pull request.

## Procedure for finding and fixing bugs

When an AI assistant is used to find and fix bugs, it follows at least these steps:

1. **Read the context.** Read this document, the [README](README.md), the relevant [docs](docs/) and
   every document mentioned in the request. Do not rely on isolated parts found by keyword search.
2. **Note the commit.** Record the commit the analysis is based on - after making sure it is the
   current `master` - and locate the bug as instructed.
3. **Verify the bug.** For any bug that is not trivial, write a reproducer, preferably a Go test next
   to the affected code that fails without the fix. Make sure it fails for the reason the bug gives,
   not for another one: a test that a wrong password would fail as well proves nothing. If the bug
   turns out not to be real, stop here and say so.
4. **Write the fix.** This step is not optional: an assistant able to find a bug is almost always
   able to fix it, and the reasoning is freshest in the same session.
5. **Build and verify.** Show that the reproducer fails without the fix and passes with it - for
   example with `git stash` of the implementation, or `go test -overlay` with the old file. Drop a fix
   that does not work and try another one. The fix must pass the
   [checks](#checks-before-a-pull-request).
6. **Commit.** One commit per problem, on a branch, with a message that describes the problem and the
   solution. Add a `Fixes:` trailer naming the commit that introduced the bug - the earliest one, found
   with `git log -S`, not a later one that only moved the code - and the `Assisted-by` trailer:

   ```text
   Fixes: 1a2b3c4d5e6f ("feat: add device metrics")
   Assisted-by: AGENT_NAME:MODEL_VERSION
   ```

   Build, vet and test every commit on its own before the pull request.
7. **Find the reviewers.** [CODEOWNERS](CODEOWNERS) names who reviews changes. Reference GitHub
   issues in the pull request description (`Fixes #123`).
8. **Say what could not be done.** If the fix could not be built or tested, or no reproducer could be
   written, say so explicitly. Unverified reports and untested fixes cost maintainers a lot of time.
9. **Classify the bug.** Use the [threat model](#threat-model) to decide whether it is a
   vulnerability or a regular bug, and leave that result to the person for review. Check whether it
   affects the latest release (`git merge-base --is-ancestor <commit> <tag>`): a fix for a released
   vulnerability needs a release too.

Regular bugs go into a pull request. Vulnerabilities are reported privately, see
[Reporting vulnerabilities](#reporting-vulnerabilities). An assistant never opens issues, pull
requests or security advisories about a vulnerability on its own.

## Threat model

wg-access-server runs with elevated network privileges (`NET_ADMIN` or root), holds the WireGuard
server's private key, sets up the host's firewall rules and keeps every device's preshared key.

**Trusted:** the operator, the configuration file, command-line flags, environment variables, the
host, and the commands the configuration runs around the interface lifecycle.

**Untrusted:**

- anybody who can reach the HTTP and HTTPS endpoints, signed in or not,
- signed-in users who are not admins, and whoever holds one of their API tokens,
- VPN clients and their traffic, including their DNS queries to the built-in proxy,
- what identity providers (OIDC, GitLab, GitHub) return beyond the identity they vouch for - names,
  emails, groups - and an identity at one provider claiming to be somebody of another,
- `X-Forwarded-For` from anybody but a configured trusted proxy.

**Admins** may manage every device and user through the web UI and the API. They must not be able
to run commands on the host, read the server's private key, or read other people's passwords,
second-factor secrets or session ids.

A bug is a **vulnerability** if an untrusted party can, for example:

- see, change, create or delete devices of other users, or reach admin functions without being one,
- sign in as somebody else, skip the second factor, keep using a session or token that was ended or
  revoked, or let a token do what it may not (create tokens, manage the account),
- read secrets: private or preshared keys, password hashes, second-factor secrets, recovery codes,
  session ids, API tokens, or the storage credentials - in responses, logs or error messages,
- reach networks outside what their access policy or `vpn.allowedIPs` allows, in either address
  family, or get past client isolation,
- run commands on the host or inject firewall rules,
- crash the server or exhaust its resources.

Bugs that need control over a trusted input, such as a broken configuration value, are regular bugs.

## Reporting vulnerabilities

Do not report vulnerabilities in public issues or pull requests. Use GitHub's private vulnerability
reporting:
[Security → Report a vulnerability](https://github.com/freifunkMUC/wg-access-server/security/advisories/new).
