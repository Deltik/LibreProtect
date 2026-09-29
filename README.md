![LibreProtect: free, private block logging, rollbacks and restores](branding/banner.svg)

[![GitHub release](https://img.shields.io/github/v/release/Deltik/LibreProtect)](https://github.com/Deltik/LibreProtect/releases)
[![GitHub downloads](https://img.shields.io/github/downloads/Deltik/LibreProtect/total?label=GitHub%20downloads)](https://github.com/Deltik/LibreProtect/releases)
[![Modrinth downloads](https://img.shields.io/modrinth/dt/libreprotect?label=Modrinth%20downloads)](https://modrinth.com/plugin/libreprotect)
[![SpigotMC downloads](https://img.shields.io/spiget/downloads/139087?label=SpigotMC%20downloads)](https://www.spigotmc.org/resources/libreprotect.139087/)
[![SpigotMC rating](https://img.shields.io/spiget/rating/139087)](https://www.spigotmc.org/resources/libreprotect.139087/)
[![CI status](https://img.shields.io/github/actions/workflow/status/Deltik/LibreProtect/ci.yml?branch=main&label=CI)](https://github.com/Deltik/LibreProtect/actions/workflows/ci.yml)

# LibreProtect

**LibreProtect** is a privacy-hardened build of [CoreProtect](https://github.com/PlayPro/CoreProtect), the block logging and rollback plugin for Minecraft servers. It is rebuilt from each CoreProtect release, automatically when possible.

* **No telemetry.** CoreProtect contacts coreprotect.net for update checks, usage statistics, error reports, donation-key checks and translations, and it bundles bStats. LibreProtect sends each of those requests through a [network policy](#configuration). By default, it answers translation requests itself, from translations it bundles, and blocks everything else except update checks. It answers those by asking GitHub or Modrinth for LibreProtect's latest release, without sending your version number, server port or license key. The `privacy-first` preset blocks update checks too.
* **Everything unlocked.** Features that CoreProtect reserves for donors work without a donation key, including [automatic purging](#automatic-purging) and [database migration](#database-migration), which LibreProtect implements itself.
* **Drop-in.** LibreProtect keeps CoreProtect's commands, permissions, API, data folder and database. Add-ons that depend on CoreProtect keep working, and you can switch back and forth between the two.

LibreProtect is an independent project. It isn't affiliated with or endorsed by CoreProtect or its authors.

## Table of Contents

* [Installation](#installation)
* [Usage](#usage)
* [Configuration](#configuration)
* [Differences from CoreProtect](#differences-from-coreprotect)
* [Compatibility](#compatibility)
* [Automatic Purging](#automatic-purging)
* [Database Migration](#database-migration)
* [License](#license)

## Installation

1. Download `LibreProtect-<version>.jar` from [GitHub Releases](https://github.com/Deltik/LibreProtect/releases), [Modrinth](https://modrinth.com/plugin/libreprotect) or [SpigotMC](https://www.spigotmc.org/resources/libreprotect.139087/).
2. Stop your server.
3. If CoreProtect is installed, remove its JAR from the `plugins/` folder.
4. Put LibreProtect's JAR in the `plugins/` folder.
5. Start your server.

CoreProtect's data and settings in `plugins/CoreProtect/` are used as they are.

LibreProtect's versions follow CoreProtect's release tags. For example, `24.1-libre1` is CoreProtect 24.1, tagged `v24.1`, with LibreProtect's changes. The number after `libre` goes up when LibreProtect changes without a new CoreProtect release.

### Verifying a Download

Each release on GitHub has build provenance, which proves that GitHub Actions built the JAR from this repository:

```sh
gh attestation verify LibreProtect-<version>.jar --repo Deltik/LibreProtect
```

Each release on GitHub also has a `.sha256` checksum file and the complete source code of the build. Releases other than development builds also have a CycloneDX software bill of materials, which lists the libraries in the JAR and those that the server downloads for it. Libraries that CoreProtect uses from the server, such as Log4j, aren't listed.

### Development Builds

Development builds of CoreProtect's unreleased code are published as [prereleases on GitHub](https://github.com/Deltik/LibreProtect/releases). Each is named after the latest CoreProtect release tag that its commit builds on, and the commit itself, such as `24.0-121-gd5cad31-libre-dev` for commit `d5cad31`, 121 commits after `v24.0`. Development builds can include database changes that released versions of CoreProtect can't read yet, so don't use them on a server whose data you care about.

## Usage

Commands, permissions and the API are CoreProtect's. See [CoreProtect's documentation](https://docs.coreprotect.net/).

LibreProtect also has its own, free implementations of two features that CoreProtect reserves for its paid builds: [automatic purging](#automatic-purging) of old data, and [database migration](#database-migration) with `/co migrate-db`.

## Configuration

CoreProtect's settings stay in `plugins/CoreProtect/config.yml`.

LibreProtect's network policy is in `plugins/CoreProtect/libreprotect.yml`. LibreProtect creates the file with default values the first time it starts. Changes take effect after a server restart. A setting that the file leaves out has its default value.

If the file is there but LibreProtect can't use it, LibreProtect uses the `privacy-first` preset, so that it makes no web requests, and logs a warning that says why. That happens when the file:

* can't be read, isn't a regular file, is larger than 1 MiB, or isn't valid YAML
* has no settings, such as an empty file. Delete it to have LibreProtect write the default file at the next start.
* has a key that isn't a setting, such as a mistyped `preset`
* names no known preset

<details><summary>Default libreprotect.yml</summary>

```yaml
# LibreProtect network policy
#
# Controls the web requests that CoreProtect makes: update checks, usage
# statistics, error reports, bStats, donation-key checks and translations.
# Connections to the databases in config.yml aren't affected.
# Changes take effect after a server restart.
#
# https://github.com/Deltik/LibreProtect

# What happens to requests that no route matches
# privacy-first - Send no web requests: LibreProtect answers translations itself and blocks the rest
# allow-updates - Answer update checks from update-sources, and send no other web requests (default)
# passthrough - Allow every request through unchanged (for debugging). Bundled translations fill any gaps
preset: allow-updates

# Where update checks go when the preset allows them
# LibreProtect asks each source in order until one answers.
# Requests name LibreProtect but carry no version, server port or key. Sources see your server's IP address.
# Each source has a type and its settings:
#   type: github, with repository: owner/name
#   type: modrinth, with project: a Modrinth project ID or slug
# Either type also takes api: the base URL of the API, for a mirror
# Set this to [] to turn update checks off
update-sources:
  - type: github
    repository: Deltik/LibreProtect
  - type: modrinth
    project: libreprotect

# Custom routes, checked in order before the preset. The first match decides.
# Each route has: pattern (regex), action (BLOCK/ANSWER/REDIRECT/PASSTHROUGH), target (for REDIRECT)
# Patterns match the whole URL with a lowercase scheme and host, without user info or fragment
# Patterns support named capture groups: (?<name>...) or (?P<name>...)
# Capture substitution in targets: ${name}
# REDIRECT targets should keep the original scheme (http or https)
# Example:
#   - pattern: "http://update\\.coreprotect\\.net(?<path>/.*)"
#     action: REDIRECT
#     target: "http://my-mirror.example${path}"
routes: []

# Log every network request that LibreProtect intercepts
verbose-logging: false
```

</details>

### `preset`

The preset decides what happens to CoreProtect's requests that no [route](#routes) matches.

**allow-updates** (default): LibreProtect answers CoreProtect's update check by asking the [update sources](#update-sources) for LibreProtect's latest release, answers translation requests itself, and blocks everything else. The update notice names the release it found and links to it. When possible, a LibreProtect release for each new CoreProtect release is built automatically. If a CoreProtect release needs changes to LibreProtect first, its LibreProtect release takes longer.

**privacy-first**: Make no web requests. LibreProtect answers translation requests itself and blocks everything else, including update checks. Connections to databases are [outside the network policy](#connections-outside-the-network-policy).

**passthrough**: Allow every request, like stock CoreProtect. This is meant for debugging. Translations from coreprotect.net are [layered over the bundled ones](#translations).

These are the requests that the presets know about:

| Destination                       | Purpose            | `allow-updates` (default) | `privacy-first` | `passthrough` |
|-----------------------------------|--------------------|---------------------------|-----------------|---------------|
| `update.coreprotect.net`          | Update check       | Answer                    | Block           | Allow         |
| `stats.coreprotect.net`           | Usage statistics   | Block                     | Block           | Allow         |
| `coreprotect.net/license/`        | Donation-key check | Block                     | Block           | Allow         |
| `coreprotect.net/translate/`      | Translations       | Answer                    | Answer          | Allow         |
| `error-reporting.coreprotect.net` | Error reports      | Block                     | Block           | Allow         |
| `bstats.org`                      | bStats metrics     | Block                     | Block           | Allow         |
| Anything else                     |                    | Block                     | Block           | Allow         |

A blocked request fails the same way it would if the server were offline, and CoreProtect carries on without it. An answered request isn't sent where CoreProtect meant it to go: LibreProtect replies to it itself. See [`ANSWER`](#routes).

### `update-sources`

Where LibreProtect looks for its own new releases when it answers CoreProtect's update check, which the `allow-updates` preset or an `ANSWER` [route](#routes) allows. Nothing is sent to update.coreprotect.net. LibreProtect asks each source in order and uses the first one that names a LibreProtect release, so the default asks GitHub, and Modrinth only if GitHub fails or names none. An empty list, `[]`, turns update checks off.

Each source has these keys:

| Key          | Required       | Value                                                                                                               |
|--------------|----------------|---------------------------------------------------------------------------------------------------------------------|
| `type`       | Yes            | `github` or `modrinth`                                                                                              |
| `repository` | For `github`   | The GitHub repository as `owner/name`, such as `Deltik/LibreProtect`                                                |
| `project`    | For `modrinth` | The Modrinth project's ID or slug, such as `libreprotect`                                                           |
| `api`        | No             | The base URL of the API, for a mirror. The defaults are `https://api.github.com` and `https://api.modrinth.com/v2`. |

Requests name LibreProtect in their `User-Agent`, but carry no version, server port or key. Like any request, they show your server's IP address to the source. They only follow redirects to the same scheme, host and port. [Routes](#routes) don't apply to them, since they are LibreProtect's own; `api` sends them to a mirror instead. GitHub's latest release and Modrinth's newest listed release count; prereleases and development builds don't. A development build is only told about releases of a CoreProtect version newer than both the tag that it's named after and the version in its code.

`check-updates: false` in CoreProtect's `config.yml` still turns update checks off, and LibreProtect honors it after `/co reload` too. LibreProtect skips an invalid source and logs a warning about it.

### `routes`

A list of custom routes that are checked before the preset. The first route that matches a request decides what happens to it. Routes apply to the requests of CoreProtect and the libraries it bundles, not to LibreProtect's own requests to the [update sources](#update-sources). Each route has these keys:

| Key       | Required       | Value                                                                                                                                                                                                                                                                                                                                                 |
|-----------|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `pattern` | Yes            | A [Java regular expression](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/regex/Pattern.html) that must match the whole URL. The scheme and host are lowercase, a default port such as `:443` is left out, and so are user info and the `#fragment`. Named groups, `(?<name>…)` or `(?P<name>…)`, can be used in `target`.   |
| `action`  | Yes            | `BLOCK`, `ANSWER`, `REDIRECT` or `PASSTHROUGH`, in any case                                                                                                                                                                                                                                                                                           |
| `target`  | For `REDIRECT` | The URL to connect to instead. `${name}` is replaced with what the named group `name` matched.                                                                                                                                                                                                                                                        |

**BLOCK**: Fail the request, as if the server were offline.

**PASSTHROUGH**: Make the request unchanged.

**REDIRECT**: Connect to `target` instead. Keep the original scheme (`http` or `https`), because CoreProtect and bStats expect a connection of that type.

**ANSWER**: LibreProtect answers the request itself, and nothing is sent to CoreProtect's servers. LibreProtect can answer these requests:

* Translations come from files bundled with LibreProtect. See [Translations](#translations).
* Update checks are answered from the [update sources](#update-sources).
* Usage statistics get an empty reply.

Any other request fails. The donation-key check can't be answered on purpose: CoreProtect would save the answer in `plugins/CoreProtect/.license`, and stock CoreProtect would trust that file if you switched back.

LibreProtect skips an invalid route and logs a warning about it.

For example, to use CoreProtect's translation service as well as the bundled translations, and to send CoreProtect's own update check to a server of yours instead of asking the update sources:

```yaml
routes:
  # Sends your language code and CoreProtect's phrases, including the ones you changed in language.yml, to coreprotect.net
  - pattern: "http://coreprotect\\.net/translate/"
    action: PASSTHROUGH
  - pattern: "http://update\\.coreprotect\\.net(?<path>/.*)"
    action: REDIRECT
    target: "http://updates.example.com${path}"
```

### `verbose-logging`

**false** (default): Log problems and which policy is active, but not individual requests.

**true**: Log every request that LibreProtect intercepts and what happened to it.

### Translations

Set `language` in CoreProtect's `config.yml`, as with stock CoreProtect. LibreProtect bundles the translations in CoreProtect's source code, which CoreProtect's own JAR doesn't include, and by default answers CoreProtect's translation request from them, so nothing is sent. Each release's `DIFFERENCES.md` lists the bundled languages. A phrase that a bundled translation lacks stays in English. So does every phrase of a language that isn't bundled, and LibreProtect logs a warning about it.

If you [allow the translation request](#routes), CoreProtect's translation service can translate phrases and languages that aren't bundled. Its translations take precedence, and the bundled ones fill any gaps, even if the service can't be reached. The request sends your language code and CoreProtect's phrases, including the ones you changed in `language.yml`.

Phrases that you change in `plugins/CoreProtect/language.yml` are never replaced by translations, and don't need a network request.

CoreProtect keeps the translations it gets, and only asks for them again after an update, a change of language, or a change to `language.yml`. LibreProtect also has it ask again when the translations would come from somewhere else, for example after you allow the translation request. It never discards translations that it can't replace, such as a translation that stock CoreProtect saved for a language that isn't bundled.

### Connections Outside the Network Policy

The network policy covers the requests that CoreProtect and the libraries it bundles make to web addresses. It doesn't cover:

* Connections to the databases in CoreProtect's `config.yml`, such as MySQL or ClickHouse, which CoreProtect, database migration and automatic purging make.
* LibreProtect's own requests to the [update sources](#update-sources). The policy decides whether LibreProtect answers CoreProtect's update check, and so whether it asks them, but routes can't block or redirect these requests. An empty `update-sources` in `libreprotect.yml`, or `check-updates: false` in CoreProtect's `config.yml`, stops them.
* The libraries that CoreProtect's `plugin.yml` lists, which the server (Paper or Spigot) downloads when it loads the plugin, before any of the plugin's code runs. For example, on CoreProtect versions that support DuckDB, the server downloads the DuckDB driver from Maven Central, or from the mirror of Maven Central that it is configured to use. Recent Paper versions use a mirror hosted by Google by default. Each release's `DIFFERENCES.md` lists these libraries under "Libraries the Server Downloads".

## Differences from CoreProtect

* The plugin is still named `CoreProtect`, so other plugins can find it, but its messages name LibreProtect. For example, `/co status` starts with `----- LibreProtect -----`.
* LibreProtect has no donation keys. Features work without one, and `/co status` has no `License:` line.
* CoreProtect's Discord link is replaced with a link to LibreProtect, and its Patreon link is left out.
* The startup log shows which network policy is active.
* LibreProtect bundles CoreProtect's [translations](#translations) and answers translation requests itself, instead of sending your phrases to coreprotect.net.
* Update checks ask [GitHub or Modrinth](#update-sources) for LibreProtect's releases instead of asking update.coreprotect.net, and the update notice shows LibreProtect's version.
* [Database migration](#database-migration) (`/co migrate-db`) and [automatic purging](#automatic-purging) (`auto-purge`) work. CoreProtect has them only in its paid builds, whose code isn't public, so LibreProtect has its own implementations.

Each release lists its exact changes in `DIFFERENCES.md`, which is attached to the release and included in the JAR. It also says which of LibreProtect's features work with the CoreProtect that the release was built from.

Please report problems with LibreProtect [here](https://github.com/Deltik/LibreProtect/issues), not to CoreProtect.

## Compatibility

LibreProtect supports the same Minecraft versions and server software as the CoreProtect release it is built from. Releases on Modrinth list them. Every build is tested on the Paper version in [`integration/paper.lock`](integration/paper.lock).

LibreProtect and CoreProtect use the same database, so you can switch between them. The integration test switches from CoreProtect to LibreProtect and back on the same data for every build.

## Automatic Purging

To remove old data every day, set `auto-purge` in CoreProtect's `config.yml` to how much data to keep:

```yaml
auto-purge: 180d
auto-purge-time: 03:30
```

* `auto-purge` takes times like CoreProtect's commands do: `y`, `mo` (30 days), `w`, `d`, `h`, `m` and `s`, which can be combined (`1y,6mo`) and can have decimals (`1.5y`). As in CoreProtect, the minimum is `30d`. `false`, the default, turns automatic purging off. So does a value that isn't valid or is below the minimum, with a warning.
* `auto-purge-time` is when to run each day, in 24-hour `HH:mm` server time. The default is midnight.

Changes apply shortly after `/co reload` or a restart. The log shows the next run, and each run logs the date it removes data from before, what it removed, and when it runs next. `/co status` shows how many rows were removed since the server started. Automatic purging trusts the server's clock, so a clock set far ahead would remove recent data.

Automatic purging runs in the background while the server stays usable:

* On SQLite, MySQL and DuckDB, it removes old rows in small chunks with pauses in between. While a chunk runs, CoreProtect may refuse a rollback, `/co reload` or `/co purge` with its message that a purge is in progress; try again a moment later. On SQLite and MySQL, the newest row of each of the `block`, `entity` and `skull` tables, and of `entity_spawn` on CoreProtect versions that have it, stays, however old it is, because SQLite, and MySQL before 8.0, could give its row ID to new data that other rows still refer to.
* On ClickHouse, CoreProtect drops the monthly partitions that are entirely older and deletes the older rows of the others in one step, which needs `database-lock: true` in `config.yml`. Until it finishes, lookups, rollbacks, `/co purge`, `/co reload` and `/co migrate-db` are refused as they are during `/co purge`, and it doesn't stop for them. A shutdown doesn't wait for it: CoreProtect cancels it, as it cancels `/co purge`, but a deletion that has started keeps running inside ClickHouse. On CoreProtect versions that look for unfinished deletions, until it finishes, the next purge is refused and CoreProtect won't start on ClickHouse.

On the other engines, a run stops when the server shuts down, a manual purge, database migration or conversion starts, or `/co consumer pause` is used. On any engine, the next run removes what a stopped run left.

If the CoreProtect that LibreProtect was built from lacks something that automatic purging needs, the log says what when `auto-purge` is on, and runs stop before they touch the database. A database engine that LibreProtect doesn't know is never purged.

Removing rows makes room for new data, but it may not shrink the database files right away. On an existing database with a lot of old data, you can run a manual purge first, such as `/co purge t:180d`, with `#optimize` on MySQL to reclaim the space.

## Database Migration

`/co migrate-db` copies all of CoreProtect's data from the database it uses now to another database, checks the copy, and switches CoreProtect to it while the server keeps running. Only the server console can run it.

```
co migrate-db <database> [--full-validation]
```

It migrates between SQLite (`sqlite`) and MySQL (`mysql`), and on CoreProtect versions that support DuckDB and ClickHouse, between any two of SQLite, MySQL, DuckDB (`duckdb`) and ClickHouse (`clickhouse`). `co migrate-db` alone shows which databases it can migrate to.

Before you start:

* Keep `database-lock: true` in `config.yml`.
* The new database must not have CoreProtect's data in it. Before migrating to SQLite, move the SQLite file away: `plugins/CoreProtect/database.db`, or the file that `sqlite-database` in `config.yml` names on CoreProtect versions with that setting. A DuckDB file, `plugins/CoreProtect/database.duckdb`, must not exist yet. A MySQL or ClickHouse database must not have CoreProtect's data under the table prefix. Other tables are left alone.
* On CoreProtect versions with the `database-type` setting in `config.yml`, leave `database-type` naming the database in use, and load the new database's settings with a restart or `/co reload` first. MySQL and ClickHouse use the `table-prefix` in `config.yml` when you migrate from SQLite or DuckDB, and keep the prefix in use when you migrate from MySQL or ClickHouse. SQLite and DuckDB always use `co_`.
* On CoreProtect versions without `database-type`, set `use-mysql` and the MySQL settings in `config.yml` for the new database, as CoreProtect's instructions say, but don't restart or use `/co reload`. LibreProtect reads the new database's settings from the file. While it copies, it sets `use-mysql` back to the database in use, so that a crash leaves CoreProtect there, and sets it to the new database when it switches.
* Don't change the new database's settings once the migration starts. LibreProtect checks them again before it copies and before it switches, and stops if they changed.
* The ClickHouse server must be a version that CoreProtect supports (see [CoreProtect's documentation](https://docs.coreprotect.net/)), with an Atomic database. Before it copies anything, the migration asks CoreProtect's own check whether the server is new enough, and stops if it isn't.

While the migration runs, CoreProtect keeps logging: new events wait in memory and go to the new database after the switch. Lookups, rollbacks, purges and `/co reload` are refused until it finishes. The console shows the progress. Don't stop the server until the migration reports its result.

Before it switches, LibreProtect checks the copy: every table's row count and row IDs, every row of small tables and reference tables, and a sample of the rows of larger tables. `--full-validation` compares every row instead. Any difference stops the migration before the switch.

Between SQLite or MySQL and DuckDB or ClickHouse, CoreProtect's own conversions change the format of some data. A value that they can't convert is copied unchanged and listed, since CoreProtect reads either format, but a migration to ClickHouse fails instead. If the conversions themselves don't work the way LibreProtect expects, the migration fails and says what changed, rather than copying unconverted data.

When it switches, LibreProtect checks that CoreProtect actually uses the new database. Then `config.yml` selects the new database, with `database-type`, or with `use-mysql` on CoreProtect versions without `database-type`. The old database is left as it was, so you can archive or delete it once you're satisfied. If the migration fails, or the server stops during it, CoreProtect keeps using the old database, and the new one is marked as unfinished so that CoreProtect won't start on it. Delete the new database before you try again.

If the CoreProtect that LibreProtect was built from lacks something that a migration needs, the command says so instead of starting: `/co migrate-db isn't available with this CoreProtect build: <reason>`, or `Migrating to <database> isn't available with this CoreProtect build: <reason>` when only some migrations are affected. For example, if CoreProtect's ClickHouse writer changed, migrating to ClickHouse is refused, but migrating from ClickHouse to another database still works.

## For Developers

You don't need these sections to run LibreProtect. They explain how it is built, released and tested.

<details><summary>How It Works</summary>

LibreProtect never edits CoreProtect's source code. Each build:

1. **Builds upstream unmodified** at a pinned commit, with upstream's own Maven build. A development build reuses upstream's build from an earlier development build in the same checkout, if it was of the same commit with the same settings. A release always builds upstream anew.
2. **Transforms the JAR** ([`transformer/`](transformer/)), rewriting bytecode by JDK and Bukkit types rather than by upstream's file layout or variable names:
   * Every call that opens a URL connection, in CoreProtect and in bundled libraries such as bStats, goes through LibreProtect's network policy instead. Network code that upstream adds later with the same APIs is covered automatically. Database drivers that upstream bundles, which connect only to the databases in `config.yml`, are reviewed and left as they are.
   * CoreProtect's donation-key checks return constants.
   * CoreProtect compares its own version with those of its database, its patches and its features. It reads that version from `plugin.yml` in `VersionUtils.getPluginVersion()`, which now reads the version that upstream's build wrote there instead of LibreProtect's. So CoreProtect behaves as upstream's own build of the same commit, whatever LibreProtect's version says. The audit asks for a review of any new upstream method that calls `getVersion()` or `getFullName()` of Bukkit's `PluginDescriptionFile`, or `getVersion()` or `getDisplayName()` of Paper's `PluginMeta`, or that has a string naming `plugin.yml`, as code that reads that file itself does.
   * Text that shows the plugin's name is rewritten to say LibreProtect. CoreProtect's phrases and the calls that print messages go through LibreProtect's branding, which names LibreProtect, points links to LibreProtect, and leaves out donation-key messages.
   * A generated subclass of CoreProtect's main class becomes the plugin's entry point. It loads the network policy before any of CoreProtect's code can open a connection.
   * LibreProtect's [runtime](runtime/) classes are added. So are its [extensions](extensions/), LibreProtect's own implementations of CoreProtect's closed-source extension points: database migration and automatic purging.
   * The translations in CoreProtect's source code, which its JAR leaves out, are added, with CoreProtect's built-in English phrases taken from its code.
3. **Checks contracts.** The build fails with an explanation if upstream breaks an assumption that the transformation relies on. For example, the main class can't be subclassed, a donation-key check was renamed, or network calls are left over.
4. **Checks what the extensions can do with this upstream.** The extensions don't link against CoreProtect's classes. They reach CoreProtect only by reflection, and each feature asks for the capabilities it needs, such as pausing CoreProtect's database writes or converting its data between database formats. The build probes the exact upstream JAR that it bundles and records what the extensions found, and the transformer checks that report against the JAR and bundles it. When upstream changes something that a feature needs, only that feature turns off, and it says why. `DIFFERENCES.md` shows how each feature works with that build's CoreProtect.
5. **Audits** upstream's JAR, as upstream built it, against [`audit/baseline.json`](audit/baseline.json), the reviewed state of the upstream lines that LibreProtect builds: the release in `upstream.lock`, and upstream's default branch. What either line has needs no review:
   * **FAIL** stops the build. It means that upstream's code does something that LibreProtect can't keep under the network policy, such as opening a raw socket. A change to upstream's license fails every build too, development builds included, until a maintainer accepts it: a license file anywhere in upstream's source, the licenses in its pom, or the license headers of its Java files.
   * **REVIEW** blocks releases, but not development builds, until a maintainer accepts the change. Examples are a new host, a change to upstream's dependencies, and a change to how the extensions work with upstream, including a change to the upstream code whose behavior they rely on, which the build fingerprints.

   The audit covers upstream's code. Besides connecting to the databases in `config.yml`, LibreProtect's own code makes one kind of network request itself: update checks to the [update sources](#update-sources), and only when the network policy answers update checks.
6. **Runs integration tests** ([`integration/`](integration/)) on real Paper servers, with a Java agent that records and blocks all outgoing network traffic, and MySQL and ClickHouse in containers:
   * One server runs on the same data with stock CoreProtect, then LibreProtect, then stock CoreProtect again. Stock CoreProtect must be seen contacting coreprotect.net, which proves that the test can see network traffic at all. LibreProtect must make no requests but the default policy's update checks, read stock CoreProtect's data, and pass API, command and message checks. Stock CoreProtect must then read LibreProtect's data.
   * More servers check that the capabilities on a running server match the report in the JAR, and test bundled and layered translations, update checks against stand-ins for GitHub and Modrinth, `/co migrate-db` through each database engine that CoreProtect supports and back, and automatic purging on each of them, including stopping and resuming.

Builds are reproducible: the same inputs produce a byte-identical JAR.

</details>

<details><summary>Automation</summary>

[`upstream-watch`](.github/workflows/upstream-watch.yml) runs on a schedule. It compares what should exist with what does, and fixes the difference:

| When                                                | Then                                                                                                                                               |
|-----------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| Upstream publishes a new release                    | Opens a pull request that updates [`upstream.lock`](upstream.lock), runs CI on it, and enables auto-merge                                          |
| `upstream.lock` on `main` has no GitHub release yet | Runs [`release`](.github/workflows/release.yml), which publishes to GitHub with provenance, an SBOM, `DIFFERENCES.md` and the complete source code |
| The newest release isn't on Modrinth                | Runs [`distribute`](.github/workflows/distribute.yml), which publishes it to Modrinth and syncs the Modrinth project's details                     |
| Upstream's default branch has a new commit          | Runs [`dev`](.github/workflows/dev.yml), which publishes a GitHub prerelease and deletes old ones                                                  |
| A pinned upstream release tag moved                 | Opens an issue                                                                                                                                     |

A bump pull request merges by itself only when CI passes: the build, the contract checks, the license notice check and the integration test must pass, and the audit must find nothing unreviewed. [CI](.github/workflows/ci.yml) also builds and tests upstream's default branch in a separate job, which shows early what CoreProtect's next release breaks, and which may fail without failing the workflow. When a release, development build or distribution fails, it opens an issue labeled `pipeline-failure`, and closes it once that pipeline passes again. A failing bump pull request shows its failure on the pull request.

Modrinth gets the Minecraft versions and server software that upstream declares for the same CoreProtect release on Modrinth, as well as upstream's categories. The Modrinth description is [`branding/description.md`](branding/description.md).

To accept upstream changes that need review, review what changed; the summary of the CI run lists the findings. Then build the same upstream with `scripts/lp build`, with `--ref` for upstream's default branch, or download the run's `dist` artifact into `dist/`, and run `scripts/lp accept`. It makes the build's line of `audit/baseline.json` what the build observed; commit that, on the pull request's branch for a bump. A finding that accepting the build doesn't resolve, such as dynamic class loading, needs an allowance with a reason in `audit/baseline.json` instead. `scripts/lp accept` accepts a change to upstream's licensing only with `--licenses`: use it only once you're sure LibreProtect may still distribute CoreProtect under the GPL. Changes under `audit/` need a code owner's approval. To release changes to LibreProtect alone, increase `FORK_REVISION` in `upstream.lock`.

</details>

<details><summary>Development</summary>

You need Git, Bash, and JDK 25 or newer with `javac`. The build looks for one in `JAVA_HOME`, on the `PATH`, and in `~/.jdks`, `/usr/lib/jvm` and `/opt`. The integration test also needs Docker or Podman for its database containers.

```sh
scripts/lp build                 # Build the release in upstream.lock into dist/LibreProtect-<version>.jar
scripts/lp build --ref master    # Build any upstream branch, tag or commit as a development build, named after git describe
scripts/lp it                    # Integration test the last build (downloads Paper once, and accepts the Minecraft EULA)
scripts/lp db up                 # Keep the database containers running between tests (db env shows them, db down removes them)
scripts/lp accept                # Accept the last build into audit/baseline.json once its audit findings are reviewed (needs jq)
scripts/lp sources               # Archive the complete source code of the last build (build from a clean commit first)
scripts/lp sbom                  # Write a CycloneDX software bill of materials of the last build (needs jq)
scripts/lp clean                 # Delete build output
scripts/lp lint                  # Check the Python code's format, lints and types (needs uv)
scripts/lp --help                # Show every command and option
branding/generate.py             # Render the images as PNGs, and the store description as BBCode, into branding/build/ (needs uv)
branding/generate.py draw        # Redraw the images' SVGs after a change to their design
DRY_RUN=1 scripts/ci/upstream-watch.sh   # Show what the scheduled reconciler would do now
```

The build runs each module's unit tests in several JVMs at once, as many as the processors and the available memory allow, up to 8. The transformer's and the extensions' tests overlap for a few seconds, with up to twice as many JVMs then. Set `LP_TEST_FORKS` to choose how many. The integration test likewise runs several Paper servers at once; `scripts/lp it --jobs N` runs up to `N`.

A development build's version is what `git describe --tags --long` says about the upstream commit, followed by `-libre-dev`: `<tag>-<commits>-g<commit>-libre-dev`. `<tag>` is upstream's nearest release tag without its `v`, `<commits>` is how many commits the build has that the tag doesn't, and `<commit>` is the start of the commit's ID. For example, `24.0-121-gd5cad31-libre-dev` is upstream's commit `d5cad31`, 121 commits past its release tag `v24.0`. When upstream tags a release on a branch of its own, as it did with 24.1, its default branch keeps the name of the tag before, although its code has the newer version. A release is named after its upstream release tag instead, such as `24.1-libre1`.

| Path                                         | Contents                                                                                                                                                                                |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [`runtime/`](runtime/)                       | Classes added to the plugin: the network policy and its routes, update checks, bundled translations and branding. Compiled against the Bukkit API, never against CoreProtect.           |
| [`extensions/`](extensions/)                 | LibreProtect's implementations of CoreProtect's closed-source extension points. They reach CoreProtect only by reflection, by capability, so one source tree works with every upstream. |
| [`transformer/`](transformer/)               | The build-time bytecode transformer, contract checks, capability report checks and audit, using [ASM](https://asm.ow2.io/)                                                              |
| [`audit/baseline.json`](audit/baseline.json) | The reviewed state of each upstream line                                                                                                                                                |
| [`integration/`](integration/)               | The egress-recording Java agent, test plugin and harness                                                                                                                                |
| [`upstream.lock`](upstream.lock)             | The upstream release that releases are built from                                                                                                                                       |
| [`scripts/`](scripts/)                       | `lp`, which developers and CI both use, plus CI helpers and the one-time `setup-github.sh`                                                                                              |
| [`branding/`](branding/)                     | The icon, banners and store description, and `generate.py`, which draws the images as SVGs and renders them as PNGs, and the description as BBCode                                     |

LibreProtect's own Java files, shell scripts and Python scripts begin with its license notice, the text in [`scripts/license-header.txt`](scripts/license-header.txt). CI checks this with `scripts/lp headers`, and `scripts/lp headers --fix` adds the notice to new files. To have Git check the files in each commit too, enable the repository's hooks once per clone with `git config core.hooksPath .githooks`.

The Python code must pass Ruff's formatter, all of Ruff's lints and all of ty's type checks. CI checks this with `scripts/lp lint`, and `scripts/lp lint --fix` formats the code and fixes what Ruff can. CI also checks that the SVGs in `branding/` are what `branding/generate.py draw` draws.

</details>

## License

LibreProtect is free software under the [GNU General Public License, version 3 or later](LICENSE).

CoreProtect is by Intelli and its contributors, under the [Artistic License 2.0](LICENSES/Artistic-2.0.txt). A LibreProtect JAR is a modified version of CoreProtect, which section 4(c)(ii) of that license allows to be distributed under the GPL. CoreProtect's own code is still available under the Artistic License 2.0 from [CoreProtect's repository](https://github.com/PlayPro/CoreProtect). See [NOTICE](NOTICE).

Every release includes `DIFFERENCES.md`, which describes how it differs from CoreProtect, and a `-sources.tar.gz` archive with the complete source code of that build: LibreProtect and CoreProtect at the exact commits it was built from.

### Trademarks

CoreProtect's license doesn't grant rights to its name. LibreProtect uses the name "CoreProtect" only to say what LibreProtect is built from and compatible with, and as the technical plugin name that other plugins and existing data folders depend on. Everything that LibreProtect presents as its own, including its messages, is named LibreProtect.
