# Operating WARDEN

## Secret and key rotation (register S4)

Every secret WARDEN loads is a Secrets Manager secret named `warden/<environment>/<name>` (settings.py; decision D5),
read when a process starts: after a rotation, restart the workers (or let the deployment roll them) and the new value
is in use. `tests/test_operations_rotation.py` fails if a secret WARDEN can load has no row here.

| Secret or key | What it unlocks | How to rotate | Overlap |
|---|---|---|---|
| `WARDEN_TEMPORAL_KEY` | decrypts every Temporal payload (codec.py) | create 32 random bytes; set it as the new `WARDEN_TEMPORAL_KEY` and move the old one into `WARDEN_TEMPORAL_KEY_PREVIOUS`; restart workers and clients | old key stays in `WARDEN_TEMPORAL_KEY_PREVIOUS` until no running workflow was started before the rotation (at most the approval TTL plus the verify window, about 7 hours); then remove it |
| `WARDEN_TEMPORAL_KEY_PREVIOUS` | decrypts payloads written before the last rotation | emptied when its keys are no longer needed (above) | - |
| `WARDEN_TEMPORAL_API_KEY` | the worker's Temporal Cloud service account | create a second API key for the same service account in Temporal Cloud, store it, restart, then delete the old key; set an expiry on every key | both keys valid until the old one is deleted |
| `WARDEN_AUDIT_KEY_PASSPHRASE` | the local audit signing key's encryption | re-encrypt the key file under a new passphrase, store the new passphrase | none needed: the key itself does not change |
| `WARDEN_SLACK_BOT_TOKEN` | posting into the incident channel | regenerate the bot token in the Slack app's settings, store it, restart | the old token stops at once: rotate in a quiet hour |
| `WARDEN_SLACK_WEBHOOK`, `WARDEN_TEAMS_WEBHOOK`, `WARDEN_WEBHOOK_URL` | posting through an incoming webhook | create a new webhook, store it, restart, delete the old one | both work until the old one is deleted |
| `WARDEN_GITHUB_TOKEN` | opening change-record issues in one repository | create a new fine-grained token limited to issues on that repository, with an expiry; store it, restart, revoke the old one | both work until the old one is revoked |
| `WARDEN_DB_DSN`, `WARDEN_DB_ADMIN_DSN`, `WARDEN_STACK_DB_WRITER_DSN`, `WARDEN_STACK_DB_READER_DSN` | the database readers and the narrow terminate role | change the role's password (or let RDS rotate the managed secret), store the new DSN, restart | a database role has one password: rotate, then restart promptly |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY` | a model provider, when it is not Bedrock | create a new key in the provider's console, store it, restart, delete the old key | both work until the old one is deleted |

Keys that are not environment secrets:

| Key | How to rotate |
|---|---|
| The audit signing key (KMS, register S12) | KMS has no automatic rotation for asymmetric keys: create a new key, point the signer at it, and keep every retired public key - `warden audit verify` checks each checkpoint with the key it was signed by (G6). |
| An approver's Ed25519 break-glass key | `warden audit keygen` a new pair, replace the public key in the approvers file through a reviewed change, destroy the old private key. |
| An approver's passkey | enrol the new passkey, remove the old credential from the approvers file; a lost device is removed at once. |
| The webhook's bearer secret (webhooks.py) | add the new secret beside the old one (both are accepted), change Alertmanager's `http_config.authorization`, then remove the old one. |
| The laptop's IAM Roles Anywhere certificate | issue a new certificate from the local CA before the old one expires (docs/OWNER-CONSOLE-STEPS.md). |
