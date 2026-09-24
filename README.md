# LibreProtect

[![GitHub release](https://img.shields.io/github/v/release/Deltik/LibreProtect)](https://github.com/Deltik/LibreProtect/releases)
[![GitHub downloads](https://img.shields.io/github/downloads/Deltik/LibreProtect/total?label=GitHub%20downloads)](https://github.com/Deltik/LibreProtect/releases)
[![Modrinth downloads](https://img.shields.io/modrinth/dt/libreprotect?label=Modrinth%20downloads)](https://modrinth.com/plugin/libreprotect)
[![SpigotMC downloads](https://img.shields.io/spiget/downloads/139087?label=SpigotMC%20downloads)](https://www.spigotmc.org/resources/libreprotect.139087/)
[![SpigotMC rating](https://img.shields.io/spiget/rating/139087)](https://www.spigotmc.org/resources/libreprotect.139087/)
[![CI status](https://img.shields.io/github/actions/workflow/status/Deltik/LibreProtect/ci.yml?branch=main&label=CI)](https://github.com/Deltik/LibreProtect/actions/workflows/ci.yml)

<!-- begin store description -->
**LibreProtect** is a privacy-hardened build of [CoreProtect](https://github.com/PlayPro/CoreProtect), the block logging and rollback plugin for Minecraft servers. It is rebuilt from each CoreProtect release, automatically when possible.

* **No phoning home.** CoreProtect contacts coreprotect.net for update checks, usage statistics, error reports, donation-key checks and translations, and it bundles bStats. LibreProtect sends each of those requests through a [network policy](#configuration). By default, it answers translation requests itself and blocks everything else.
* **Everything unlocked.** Features that CoreProtect reserves for donors work without a donation key.
* **Drop-in.** LibreProtect keeps CoreProtect's commands, permissions, API, data folder and database. Add-ons that depend on CoreProtect keep working, and you can switch back and forth between the two.

LibreProtect is an independent project. It isn't affiliated with or endorsed by CoreProtect or its authors.
<!-- end store description -->

## Table of Contents

* [Installation](#installation)
* [Usage](#usage)
* [Configuration](#configuration)
* [Differences from CoreProtect](#differences-from-coreprotect)
* [Compatibility](#compatibility)
* [License](#license)

<!-- begin store description -->
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

Each release on GitHub also has a `.sha256` checksum file and the complete source code of the build. Releases other than development builds also have a CycloneDX software bill of materials, which lists the libraries in the JAR.

### Development Builds

Development builds of CoreProtect's unreleased code are published as [prereleases on GitHub](https://github.com/Deltik/LibreProtect/releases). Each is named after the latest CoreProtect release tag that its commit builds on, and the commit itself, such as `24.0-121-gd5cad31-libre-dev` for commit `d5cad31`, 121 commits after `v24.0`. Development builds can include database changes that released versions of CoreProtect can't read yet, so don't use them on a server whose data you care about.

## Usage

Commands, permissions and the API are CoreProtect's. See [CoreProtect's documentation](https://docs.coreprotect.net/).

## Configuration

CoreProtect's settings stay in `plugins/CoreProtect/config.yml`.

LibreProtect's network policy is in `plugins/CoreProtect/libreprotect.yml`. LibreProtect creates the file with default values the first time it starts. Changes take effect after a server restart. A setting that the file leaves out has its default value. If the file can't be read, LibreProtect makes no web requests.

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
# privacy-first - Send no web requests: LibreProtect answers translations itself and blocks the rest (default)
# allow-updates - Like privacy-first, but LibreProtect also answers update checks
# passthrough - Allow every request through unchanged (for debugging)
preset: privacy-first

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

**privacy-first** (default): Make no web requests. LibreProtect answers translation requests itself and blocks everything else, including update checks. Connections to databases are [outside the network policy](#connections-outside-the-network-policy).

**allow-updates**: Like `privacy-first`, but LibreProtect also answers CoreProtect's update check, with the running version, so no update is announced. When possible, a LibreProtect release for each new CoreProtect release is built automatically. If a CoreProtect release needs changes to LibreProtect first, its LibreProtect release takes longer.

**passthrough**: Allow every request, like stock CoreProtect. This is meant for debugging.

These are the requests that the presets know about:

| Destination                       | Purpose            | `privacy-first` (default) | `allow-updates` | `passthrough` |
|-----------------------------------|--------------------|---------------------------|-----------------|---------------|
| `update.coreprotect.net`          | Update check       | Block                     | Answer          | Allow         |
| `stats.coreprotect.net`           | Usage statistics   | Block                     | Block           | Allow         |
| `coreprotect.net/license/`        | Donation-key check | Block                     | Block           | Allow         |
| `coreprotect.net/translate/`      | Translations       | Answer                    | Answer          | Allow         |
| `error-reporting.coreprotect.net` | Error reports      | Block                     | Block           | Allow         |
| `bstats.org`                      | bStats metrics     | Block                     | Block           | Allow         |
| Anything else                     |                    | Block                     | Block           | Allow         |

A blocked request fails the same way it would if the server were offline, and CoreProtect carries on without it. An answered request isn't sent where CoreProtect meant it to go: LibreProtect replies to it itself. See [`ANSWER`](#routes).

### `routes`

A list of custom routes that are checked before the preset. The first route that matches a request decides what happens to it. Each route has these keys:

| Key       | Required       | Value                                                                                                                                                                                                                                                                                                                                                 |
|-----------|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `pattern` | Yes            | A [Java regular expression](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/regex/Pattern.html) that must match the whole URL. The scheme and host are lowercase, a default port such as `:443` is left out, and so are user info and the `#fragment`. Named groups, `(?<name>…)` or `(?P<name>…)`, can be used in `target`.   |
| `action`  | Yes            | `BLOCK`, `ANSWER`, `REDIRECT` or `PASSTHROUGH`, in any case                                                                                                                                                                                                                                                                                           |
| `target`  | For `REDIRECT` | The URL to connect to instead. `${name}` is replaced with what the named group `name` matched.                                                                                                                                                                                                                                                        |

**BLOCK**: Fail the request, as if the server were offline.

**PASSTHROUGH**: Make the request unchanged.

**REDIRECT**: Connect to `target` instead. Keep the original scheme (`http` or `https`), because CoreProtect and bStats expect a connection of that type.

**ANSWER**: LibreProtect answers the request itself, and nothing is sent to CoreProtect's servers. LibreProtect can answer these requests:

* A translation request gets no translations.
* An update check gets the running version, so no update is announced.
* Usage statistics get an empty reply.

Any other request fails. The donation-key check can't be answered on purpose: CoreProtect would save the answer in `plugins/CoreProtect/.license`, and stock CoreProtect would trust that file if you switched back.

LibreProtect skips an invalid route and logs a warning about it.

For example, to use CoreProtect's translation service, and to send CoreProtect's own update check to a server of yours:

```yaml
routes:
  # Sends your language code and CoreProtect's phrases to coreprotect.net
  - pattern: "http://coreprotect\\.net/translate/"
    action: PASSTHROUGH
  - pattern: "http://update\\.coreprotect\\.net(?<path>/.*)"
    action: REDIRECT
    target: "http://updates.example.com${path}"
```

### `verbose-logging`

**false** (default): Log problems and which policy is active, but not individual requests.

**true**: Log every request that LibreProtect intercepts and what happened to it.

### Connections Outside the Network Policy

The network policy covers the requests that CoreProtect and the libraries it bundles make to web addresses. It doesn't cover:

* Connections to the databases in CoreProtect's `config.yml`, such as MySQL or ClickHouse, which CoreProtect makes.

## Differences from CoreProtect

* The plugin is still named `CoreProtect`, so other plugins can find it, but its messages name LibreProtect. For example, `/co status` starts with `----- LibreProtect -----`.
* LibreProtect has no donation keys. Features work without one, and `/co status` has no `License:` line.
* CoreProtect's Discord link is replaced with a link to LibreProtect, and its Patreon link is left out.
* The startup log shows which network policy is active.
* Translations from coreprotect.net are blocked unless you [allow them](#routes).
* `/co migrate-db` and automatic purging (`auto-purge`) exist only in CoreProtect's paid builds, and their code isn't public. LibreProtect has placeholders that say so. [Free implementations are welcome.](runtime/src/main/java/net/coreprotect/utility/extensions/)

Each release lists its exact changes in `DIFFERENCES.md`, which is attached to the release and included in the JAR.

Please report problems with LibreProtect [here](https://github.com/Deltik/LibreProtect/issues), not to CoreProtect.

## Compatibility

LibreProtect supports the same Minecraft versions and server software as the CoreProtect release it is built from. Releases on Modrinth list them. Every build is tested on the Paper version in [`integration/paper.lock`](integration/paper.lock).

LibreProtect and CoreProtect use the same database, so you can switch between them. The integration test switches from CoreProtect to LibreProtect and back on the same data for every build.
<!-- end store description -->

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
   * LibreProtect's [runtime](runtime/) classes are added, including placeholders for CoreProtect's closed-source extension points: database migration and automatic purging.
3. **Checks contracts.** The build fails with an explanation if upstream breaks an assumption that the transformation relies on. For example, the main class can't be subclassed, a donation-key check was renamed, or network calls are left over.
4. **Audits** upstream's JAR, as upstream built it, against [`audit/baseline.json`](audit/baseline.json), the reviewed state of upstream:
   * **FAIL** stops the build. It means that upstream's code does something that LibreProtect can't keep under the network policy, such as opening a raw socket.
   * **REVIEW** blocks releases, but not development builds, until a maintainer accepts the change. Examples are a new host and a change to upstream's dependencies or license.

5. **Runs integration tests** ([`integration/`](integration/)) on a real Paper server, with a Java agent that records and blocks all outgoing network traffic, and MySQL and ClickHouse in containers:
   * The server runs on the same data with stock CoreProtect, then LibreProtect, then stock CoreProtect again. Stock CoreProtect must be seen contacting coreprotect.net, which proves that the test can see network traffic at all. LibreProtect must make no requests, read stock CoreProtect's data, and pass API, command and message checks. Stock CoreProtect must then read LibreProtect's data.

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

A bump pull request merges by itself only when CI passes: the build, the contract checks, the license notice check and the integration test must pass, and the audit must find nothing unreviewed. When a release, development build or distribution fails, it opens an issue labeled `pipeline-failure`, and closes it once that pipeline passes again. A failing bump pull request shows its failure on the pull request.

Modrinth gets the Minecraft versions and server software that upstream declares for the same CoreProtect release on Modrinth, as well as upstream's categories. The Modrinth description is the part of this README between `begin store description` and `end store description` comments.

To accept upstream changes that need review, open the failing CI run's summary and review what changed. Then update `audit/baseline.json` in the pull request with the reviewed values from `audit-observed.json`, which the `dist` artifact includes, and merge it. Changes under `audit/` need a code owner's approval. To release changes to LibreProtect alone, increase `FORK_REVISION` in `upstream.lock`.

</details>

<details><summary>Development</summary>

You need Git, Bash, and JDK 25 or newer with `javac`. The build looks for one in `JAVA_HOME`, on the `PATH`, and in `~/.jdks`, `/usr/lib/jvm` and `/opt`. The integration test also needs Docker or Podman for its database containers.

```sh
scripts/lp build                 # Build the release in upstream.lock into dist/LibreProtect-<version>.jar
scripts/lp build --ref master    # Build any upstream branch, tag or commit as a development build, named after git describe
scripts/lp it                    # Integration test the last build (downloads Paper once, and accepts the Minecraft EULA)
scripts/lp db up                 # Keep the database containers running between tests (db env shows them, db down removes them)
scripts/lp sources               # Archive the complete source code of the last build (build from a clean commit first)
scripts/lp clean                 # Delete build output
scripts/lp --help                # Show every command and option
DRY_RUN=1 scripts/ci/upstream-watch.sh   # Show what the scheduled reconciler would do now
```

The build runs each module's unit tests in several JVMs at once, as many as the processors and the available memory allow, up to 8. Set `LP_TEST_FORKS` to choose how many. The integration test likewise runs several Paper servers at once; `scripts/lp it --jobs N` runs up to `N`.

A development build's version is what `git describe --tags --long` says about the upstream commit, followed by `-libre-dev`: `<tag>-<commits>-g<commit>-libre-dev`. `<tag>` is upstream's nearest release tag without its `v`, `<commits>` is how many commits the build has that the tag doesn't, and `<commit>` is the start of the commit's ID. For example, `24.0-121-gd5cad31-libre-dev` is upstream's commit `d5cad31`, 121 commits past its release tag `v24.0`. When upstream tags a release on a branch of its own, as it did with 24.1, its default branch keeps the name of the tag before, although its code has the newer version. A release is named after its upstream release tag instead, such as `24.1-libre1`.

| Path                                         | Contents                                                                                                                                                                                                                                      |
|----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [`runtime/`](runtime/)                       | Classes added to the plugin: the network policy and its routes, branding, and placeholders for CoreProtect's closed-source extension points. Compiled against the Bukkit API, never against CoreProtect.                                      |
| [`transformer/`](transformer/)               | The build-time bytecode transformer, contract checks and audit, using [ASM](https://asm.ow2.io/)                                                                                                                                              |
| [`audit/baseline.json`](audit/baseline.json) | The reviewed state of upstream                                                                                                                                                                                                                |
| [`integration/`](integration/)               | The egress-recording Java agent, test plugin and harness                                                                                                                                                                                      |
| [`upstream.lock`](upstream.lock)             | The upstream release that releases are built from                                                                                                                                                                                             |
| [`scripts/`](scripts/)                       | `lp`, which developers and CI both use, plus CI helpers and the one-time `setup-github.sh`                                                                                                                                                    |

LibreProtect's own Java files and shell scripts begin with its license notice, the text in [`scripts/license-header.txt`](scripts/license-header.txt). CI checks this with `scripts/lp headers`, and `scripts/lp headers --fix` adds the notice to new files. To have Git check the files in each commit too, enable the repository's hooks once per clone with `git config core.hooksPath .githooks`.

</details>

<!-- begin store description -->
## License

LibreProtect is free software under the [GNU General Public License, version 3 or later](LICENSE).

CoreProtect is by Intelli and its contributors, under the [Artistic License 2.0](LICENSES/Artistic-2.0.txt). A LibreProtect JAR is a modified version of CoreProtect, which section 4(c)(ii) of that license allows to be distributed under the GPL. CoreProtect's own code is still available under the Artistic License 2.0 from [CoreProtect's repository](https://github.com/PlayPro/CoreProtect). See [NOTICE](NOTICE).

Every release includes `DIFFERENCES.md`, which describes how it differs from CoreProtect, and a `-sources.tar.gz` archive with the complete source code of that build: LibreProtect and CoreProtect at the exact commits it was built from.

### Trademarks

CoreProtect's license doesn't grant rights to its name. LibreProtect uses the name "CoreProtect" only to say what LibreProtect is built from and compatible with, and as the technical plugin name that other plugins and existing data folders depend on. Everything that LibreProtect presents as its own, including its messages, is named LibreProtect.
<!-- end store description -->
