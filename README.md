# signssh

A cross-platform SSH client wrapper that signs with remotely-held keys through an ephemeral SSH agent, so a private key never has to live on the workstation.

`signssh` retrieves the public key from a given provider, begins an ephemeral OpenSSH-compatible agent on a private IPC socket, runs the `ssh` command using the agent, and tears the socket down on exit. Every signing operation is delegated to the provider (with external key management systems, the private key never leaves the vault/HSM). **Note:** The 'local' provider is mainly for testing and still uses local private keys.

## Install

Download and extract [the newest release of signssh](https://github.com/GoodiesHQ/signssh/releases) for your operating system and place it in your `PATH`.

```sh
# basic build for the current system
go build -o signssh ./cmd

# build release binaries for every OS/arch:
go run ./builder/builder.go -name signssh -all -release
```

Requires the OpenSSH `ssh` client also somewhere in `PATH`.

## Usage

While `signssh` can be used each time filling it with parameters and subcommands, it's more common to set environment variables which set the default values for various subcommands and parameters. All parameters can be overriden by being verbose

```sh
signssh <provider> [options] <key-name> [user@]<host>[:port] [-- <ssh args>]
signssh <provider> --list
signssh <provider> <key-name> --public
```

Examples (with explicit provider):
```sh
# show a list of all keys
signssh azure-key-vault \ 
    --azure-tenant-id="094e7e21-e8c5-49c2-b55a-5b6e65b5ab92" \ 
    --azure-client-id="f836a90b-8323-45ea-b141-e352a9de535a" \ 
    --azure-key-vault="my-azure-key-vault-wus" \ 
    --azure-environment="global" \ 
    --list
```


Examples (with environment variables defined)
```sh
# Environment variables defined in dotfiles, registry, startup scripts, etc...
export SIGNSSH_PROVIDER="azure-key-vault"
export SIGNSSH_AZURE_TENANT_ID="094e7e21-e8c5-49c2-b55a-5b6e65b5ab92"
export SIGNSSH_AZURE_CLIENT_ID="f836a90b-8323-45ea-b141-e352a9de535a"
export SIGNSSH_AZURE_KEY_VAULT="my-azure-key-vault-wus"
export SIGNSSH_AZURE_ENVIRONMENT="global"
export SIGNSSH_USERNAME="azureuser"

# ...

# Examples with implicit parameters as defined above
signssh my-key --public
signssh user@server:2222
```

Run `signssh <provider> --help` to see only that provider's options.

## Passing options to ssh

Anything after `--` is forwarded exactly as-is to the underlying `ssh` command, in the option position. Use it for legacy devices and any other `ssh` flag:

**Example:**
```sh
signssh azure-key-vault sw-key admin@old-switch -- -oKexAlgorithms=+diffie-hellman-group14-sha1
```

For a whole fleet, set `SIGNSSH_SSH_ARGS` instead of typing `--` every time; its whitespace-separated words are appended to every connection:

```sh
export SIGNSSH_SSH_ARGS="-oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa"
signssh admin@old-switch
```

Command-line `--` args are placed before `SIGNSSH_SSH_ARGS`, and both come after signssh's own `-o` settings — `ssh` honors the first value it sees for an option, so signssh's agent/auth settings and an explicit port in the destination cannot be overridden this way. Your normal `~/.ssh/config` is still read, so `Host` blocks work too. `SIGNSSH_SSH_ARGS` is split on spaces; for a value containing spaces (e.g. `ProxyCommand`), use `--` on the command line.

## Providers

### azure-key-vault

Signs with an RSA (2048/3072/4096) or EC (P-256/384/521) key in an Azure Key Vault. No client secret is involved. Instead, authentication is an interactive browser sign-in (cached to the local OS keychain after the first run). If the system has a managed identity, it is tried automatically first.

| flag | env | description |
|---|---|---|
| `--azure-tenant-id` | `SIGNSSH_AZURE_TENANT_ID` | Azure Tenant ID |
| `--azure-client-id` | `SIGNSSH_AZURE_CLIENT_ID` | Azure Client ID - defaults to the Azure CLI public client |
| `--azure-key-vault` | `SIGNSSH_AZURE_KEY_VAULT` | The name of the Azure Key Vault |
| `--azure-environment` | `SIGNSSH_AZURE_ENVIRONMENT` | Can be: `global` (default), `government`, or `china` |

### local

Signs with an on-disk OpenSSH private key (RSA, ECDSA, or Ed25519). It discovers any defaults that exist such as `~/.ssh/id_ed25519`, `~/.ssh/id_ecdsa`, `~/.ssh/id_rsa` `--local-key-path` adds more. Each key is addressed by its **filename** (`signssh local --list` shows them).

| flag | env |
|---|---|
| `--local-key-path` | `SIGNSSH_LOCAL_KEY_PATH` |
| `--local-key-password` | `SIGNSSH_LOCAL_KEY_PASSWORD` |

## Configuration via environment

Every option can come from an environment variable, and the provider itself is selected by `SIGNSSH_PROVIDER`. This lets an operator push the **non-sensitive** configuration once system-wide via `/etc/environment`, a shell profile, or an MDM/Group Policy profile, so day to day a user only types:

```sh
signssh user@host
signssh --list
signssh --public
```

### Common options

| variable | selects | sensitive |
|---|---|---|
| `SIGNSSH_PROVIDER` | which provider subcommand to run when none is typed | no |
| `SIGNSSH_KEY` | default key name (used when no `<key-name>` argument is given) | no |
| `SIGNSSH_USERNAME` | default SSH username (a `user@` in the destination will override) | no |
| `SIGNSSH_PREFIX` | prepended to `<key-name>`, stripped from `--list` output | no |
| `SIGNSSH_DEBUG` | `-vvv` passthrough to `ssh` | no |
| `SIGNSSH_SSH_ARGS` | extra `ssh` options appended to every connection | no |

Everything for `azure-key-vault` above is an identifier, not a secret, and is
safe to distribute.

### Example rollout

System-wide (same for everyone):

```sh
# Everyone will use AKV
SIGNSSH_PROVIDER="azure-key-vault"

SIGNSSH_AZURE_ENVIRONMENT="global"
SIGNSSH_AZURE_TENANT_ID="094e7e21-e8c5-49c2-b55a-5b6e65b5ab92"
SIGNSSH_AZURE_CLIENT_ID="f836a90b-8323-45ea-b141-e352a9de535a"
SIGNSSH_AZURE_KEY_VAULT="company-ssh-wus2"
```

Per-user (e.g. login script):

```sh
SIGNSSH_KEY=bob
```

Now `signssh bob@server1.contoso.com` selects the vault, picks Bob's key, prompts the user to sign in through the browser (on first use or after cache expiration), and connects. `signssh --list` and `signssh <key-name> --public` work the same way. An explicit `signssh local …` still overrides `SIGNSSH_PROVIDER`.

## Exit status

`signssh` passes `ssh`'s exit code straight through (e.g. `255` when the
connection fails, `130` when you interrupt it), returns `2` for a usage error,
`130` when interrupted during setup, and `1` for anything else.
