# Security Policy

Please report security problems privately, through [GitHub's private vulnerability reporting](https://github.com/Deltik/LibreProtect/security/advisories/new), not in a public issue.

A security problem in LibreProtect includes any network request that CoreProtect, or a library bundled with it, makes although the network policy in `libreprotect.yml` should have blocked it.

These connections are outside the network policy, and its routes never block or redirect them:

- Connections to the databases configured in CoreProtect's `config.yml`, such as MySQL or ClickHouse, which CoreProtect's database drivers make.

LibreProtect is rebuilt from each CoreProtect release, automatically when possible, so fixes are released with the next build. Only the newest release is supported.

Security problems in CoreProtect itself also affect LibreProtect, but they belong to [CoreProtect](https://github.com/PlayPro/CoreProtect). If you aren't sure where a problem belongs, report it here.
