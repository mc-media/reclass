# ansible-vault support

reclass can process values encrypted with `ansible-vault` that appear
anywhere under `parameters:` or `exports:` in the inventory.

Both forms ansible produces are accepted:

```yaml
parameters:
  # what "ansible-vault encrypt_string" emits
  client_secret: !vault |
    $ANSIBLE_VAULT;1.1;AES256
    64633564393131326139326365666366...

  # a plain block scalar works too
  cookie_secret: |
    $ANSIBLE_VAULT;1.1;AES256
    64653766373662383039363839326439...
```

A value is recognised as encrypted when it starts with `$ANSIBLE_VAULT`. The
`!vault` tag is unwrapped to its scalar payload before that check, so a
`SafeLoader` no longer rejects it.

## Modes

The behaviour is controlled by the `vault_mode` setting, which can be set in
`reclass-config.yml` or passed to `Settings()` when using reclass as a
library.

| Mode | Behaviour |
|---|---|
| `redact` | Replace the value with `***VAULTED***`. **This is the default.** |
| `decrypt` | Decrypt the value. Requires ansible and a password file. |
| `keep` | Leave the ciphertext untouched. |

The default is `redact` rather than `decrypt` on purpose: a consumer of the
reclass API that has not explicitly asked for secrets cannot leak them. The
Ansible adapter (`reclass-ansible`) sets `decrypt` for you, and a
`reclass-config.yml` can override it back if you want to inspect an
inventory without holding the vault password.

## Password

In `decrypt` mode the password is read from the file named by the
`ANSIBLE_VAULT_PASSWORD_FILE` environment variable — the same variable
ansible itself uses. Trailing whitespace is stripped.

If the variable is unset, the file is unreadable or empty, or the password
is wrong, reclass fails with an error. It does **not** silently fall back to
emitting the ciphertext: that would deploy an encrypted blob as a
configuration value without any warning.

## Notes

- `ansible` is an optional dependency, imported lazily. reclass works
  without it in `redact` and `keep` modes.
- Decrypted values are cached in memory for the lifetime of the process,
  keyed by a digest of the ciphertext. Vault uses PBKDF2 with 10000
  iterations, so decrypting the same value once per referencing class would
  be noticeable on a large inventory.
- A decrypted value is never run through the reclass reference parser, so a
  secret containing `${`, `}` or `\` is taken literally.
- Encrypted values can be referenced normally. If `secret` is encrypted,
  `${secret}` inside another string resolves to the plaintext in `decrypt`
  mode, and to `***VAULTED***` in `redact` mode.
- Anything reclass emits in `decrypt` mode is plaintext. An external
  inventory script talks JSON, so there is no way to hand ansible a value
  that stays encrypted in memory. Treat `reclass --inventory` output, and
  any log capturing it, as secret material.
