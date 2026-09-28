![LibreProtect: free, private block logging, rollbacks and restores](https://raw.githubusercontent.com/Deltik/LibreProtect/main/branding/banner.svg)

[![GitHub release](https://img.shields.io/github/v/release/Deltik/LibreProtect?style=for-the-badge)](https://github.com/Deltik/LibreProtect/releases)
[![GitHub downloads](https://img.shields.io/github/downloads/Deltik/LibreProtect/total?style=for-the-badge)](https://github.com/Deltik/LibreProtect/releases)
[![SpigotMC rating](https://img.shields.io/spiget/rating/139087?style=for-the-badge)](https://www.spigotmc.org/resources/libreprotect.139087/)

**LibreProtect** is a privacy-hardened build of [CoreProtect](https://github.com/PlayPro/CoreProtect), the block logging and rollback plugin. It is rebuilt from each CoreProtect release.

* **No telemetry.** By default, LibreProtect blocks CoreProtect's usage statistics, error reports, bStats and donation-key checks, and answers translation requests itself from translations it bundles. It answers update checks by asking GitHub or Modrinth for LibreProtect's latest release, without sending your version number, server port or license key. The `privacy-first` preset blocks update checks too.
* **Everything unlocked.** Features that CoreProtect reserves for donors work without a donation key, including automatic purging (`auto-purge`) and database migration (`/co migrate-db`), which LibreProtect implements itself.
* **Drop-in.** LibreProtect keeps CoreProtect's commands, permissions, API, data folder and database. Add-ons that depend on CoreProtect keep working, and you can switch back and forth between the two.

## Installation

1. Download LibreProtect from [GitHub](https://github.com/Deltik/LibreProtect/releases), [Modrinth](https://modrinth.com/plugin/libreprotect) or [SpigotMC](https://www.spigotmc.org/resources/libreprotect.139087/).
2. Stop your server.
3. If CoreProtect is installed, remove its JAR from the `plugins/` folder.
4. Put LibreProtect's JAR in the `plugins/` folder.
5. Start your server.

CoreProtect's data and settings in `plugins/CoreProtect/` are used as they are.

## Usage, Configuration and Features

Commands, permissions and the API are CoreProtect's. See [CoreProtect's documentation](https://docs.coreprotect.net/).

LibreProtect's [network policy](https://github.com/Deltik/LibreProtect#configuration), [automatic purging](https://github.com/Deltik/LibreProtect#automatic-purging) and [database migration](https://github.com/Deltik/LibreProtect#database-migration) are documented in [the GitHub project README](https://github.com/Deltik/LibreProtect#readme).

## Compatibility

LibreProtect supports the same Minecraft versions and server software as the CoreProtect release it is built from. LibreProtect and CoreProtect use the same database, so you can switch between them.

More compatibility information can be found in [the GitHub project README](https://github.com/Deltik/LibreProtect#compatibility).

## Support

Please report problems with LibreProtect [on GitHub](https://github.com/Deltik/LibreProtect/issues), not to CoreProtect.

## License

LibreProtect is free software under the GNU General Public License, version 3 or later. Its source code is [on GitHub](https://github.com/Deltik/LibreProtect).

LibreProtect is an independent project. It isn't affiliated with or endorsed by CoreProtect or its authors.
