# VeloxVPN operations

## First start

Run VeloxVPN with an explicit configuration path:

```bash
veloxvpn --config /opt/veloxvpn-test/config.json
```

The first start creates `config.json`, `cert.pem`, `key.pem`, and
`initial-admin-password.txt`. All secret-bearing files are owner-readable only
on Unix. Read the bootstrap password once, change it in the admin UI, and remove
the bootstrap file.

Keep the web listener on loopback and reach it through an SSH tunnel:

```bash
ssh -L 18080:127.0.0.1:18080 server
```

## Health check

The built-in health command queries the deliberately redacted public endpoint,
uses bounded timeouts, and returns a non-zero exit code if the endpoint is
unreachable or any node reports failure:

```bash
veloxvpn health --url http://127.0.0.1:18080/api/status
```

The endpoint can also be inspected directly:

```bash
curl --fail --silent http://127.0.0.1:18080/api/status
```

Full node addresses, runtime failures, and subscription details require an
authenticated session and are available at `/api/admin/status`.

## Backup and restore

1. Stop the service.
2. Copy `config.json`, `cert.pem`, and `key.pem` to encrypted storage.
3. Restore all three files together with mode `0600` and the service account as
   owner.
4. Start the service and verify `/api/status` before exposing client ports.

Never include passwords, UUIDs, tokens, private keys, or full subscription URLs
in issue reports or acceptance-test reports.

## Upgrade and rollback

1. Run the local test, format, and Clippy gates.
2. Back up the current binary and configuration.
3. Replace only the binary, restart, and check listener/runtime status.
4. If any inbound reports `failed`, restore the previous binary and backup.

Node changes made through the admin API are validated and persisted atomically.
If a new listener cannot start, VeloxVPN restores the previous configuration.

## SSH hardening after acceptance

If a root password was shared during acceptance, rotate it immediately after
the isolated test service is stopped. Install and verify an administrator SSH
public key in a second session before changing SSH policy. After key login is
confirmed, disable root password login with an SSH server drop-in equivalent to:

```text
PermitRootLogin prohibit-password
PasswordAuthentication no
```

Validate the SSH configuration before reloading the daemon, and keep the
existing session open until a new key-authenticated session succeeds. Never put
the replacement password or a private SSH key in this repository or an
acceptance report.
