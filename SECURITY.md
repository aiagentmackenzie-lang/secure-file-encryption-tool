# Security Policy

## Supported versions

| Version | Supported |
| :------ | :-------- |
| 1.0.x   | ✅        |

## Reporting vulnerabilities

Open a GitHub issue or contact the maintainer directly. Do not disclose publicly until a fix is released.

## Known limitations

- Password input requires an interactive TTY. Piped passwords are intentionally rejected.
- Argon2id parameters are fixed in the current file format. Changing them invalidates existing files.
- The CLI is not yet covered by automated tests because it requires terminal interaction.
- The tool does not protect against a compromised host OS, keyloggers, or weak/reused passwords.
