# AuthMe Fabric

A faithful **server-side Fabric port of [AuthMeReloaded](https://github.com/AuthMe/AuthMeReloaded)** — the authentication plugin for offline-mode Minecraft servers.

AuthMe Reloaded is GPL-3.0 licensed, so this derivative port is GPL-3.0 too.

> **Why this port?** The original AuthMe is a Bukkit/Spigot/Paper/Folia plugin and does not run on Fabric.
> This project brings the same account database, password hashing and authentication
> workflow to Fabric servers, so you can:
> - run a pure-Fabric offline-mode server with full password authentication, and/or
> - keep a single shared MySQL/MariaDB/PostgreSQL account database between a Bukkit/Spigot
>   AuthMe install and a Fabric server, so player accounts stay in sync across both.

---

## Feature parity with AuthMe

### Authentication
- `/login`, `/register`, `/changepassword`, `/logout`, `/unregister`
- **Session login** (skip re-login for a configurable time)
- **Captcha** after too many failed logins (`/captcha`)
- **2FA / TOTP** (RFC 6238, Google-Authenticator compatible) — `/2fa add`, `/2fa remove <code>`, `/2fa <code>`
- **Email** add/show (`/email add|show`)
- **AntiBot** rate-limiting of new connections
- **Premium bypass** (skip password auth for Mojang-verified accounts) via `/premium` / `/freemium`, or via a verified UUID forwarded by an online-mode proxy

### Unauthenticated protection
Unauthenticated players are sandboxed until they log in:
- **Movement freeze** with configurable radius (cancels movement via teleport-back)
- **Chat blocking** (chat messages from unauthenticated players are dropped)
- **Interaction blocking** — left/right click on blocks, items, and entities is cancelled
- **Damage blocking** — unauthenticated players cannot take damage
- **Command allow-list** — only configured commands (default: `login`, `register`, `l`, `reg`, `authme`, `email`, `2fa`, `totp`, `captcha`) may be used; everything else is cancelled via a Brigadier `CommandDispatcher` mixin
- **Inventory-click blocking** via a `ServerGamePacketListenerImpl#handleContainerClick` mixin (equivalent to upstream's PacketEvents-based inventory protection, but without the PacketEvents dependency)

### Admin commands (`/authme ...`, op-level only)
- `register <player> <password>`
- `unregister <player>`
- `setpassword <player> <password>`
- `auth <player>` / `unauth <player>` — toggle a player's authenticated state in the database
- `accountdata <player>`
- `reload` — reload config + messages + database connection
- `converter list` / `converter <id> [arg]` — run an account import / migration (`sqliteToSql` is implemented; other auth plugins are listed as stubs pending schema work)
- `backup`, `version`

### Password hashing — byte-identical to AuthMe
Hashes computed by this port are interchangeable with the original plugin. Default is `SHA256`:

| Algorithm | Status | Format |
|---|---|---|
| **SHA256** *(default)* | ✅ live | `$SHA$<salt16hex>$<sha256(sha256(pw)+salt)>` |
| SHA512 / SHA1 / MD5 / DOUBLE_SHA512 / PLAINTEXT | ✅ live | single hash (hex) |
| SALTEDSHA256 / SALTEDSHA512 / SALTED2MD5 | ✅ live | `hash(pw + salt)`, salt in a separate column |
| BCRYPT (`2a`) / BCRYPT2Y (`2y`) | ✅ live | BCrypt via BouncyCastle `OpenBSDBCrypt` |
| PBKDF2 / PBKDF2BASE64 | ✅ live | BouncyCastle `PKCS5S2ParametersGenerator` (HmacSHA256) |
| ARGON2 / ARGON2ID | ✅ live | BouncyCastle `Argon2BytesGenerator`, PHC `$argon2i$`/`$argon2id$` format |
| LFBCRYPT, MYBB, IPB3/4, JOOMLA, WORDPRESS, WBB3/4, PHPBB, PHPFUSION, SMF, XFBCRYPT, ROYALAUTH, CRAZYCRYPT1, CMW, MD5VB, PBKDF2DJANGO, TWO_FACTOR | 🚧 stub | listed but not implemented — tracked as a follow-up |

Plus **legacy-hash fallback with re-hash**: when a password verifies against a configured
`settings.security.legacyHashes` algorithm, it is transparently re-hashed with the primary
algorithm, so you can migrate hash functions with zero downtime.

---

## Coverage matrix — pick one jar for your MC version

The Fabric / Minecraft API drifted across versions enough that one jar cannot cover everything.
The project is split into **modules sharing a pure-Java `authme-core`**:

| Module | Minecraft | Java | fabric.mod.json `minecraft` constraint |
|---|---|---|---|
| `authme-fabric` | **1.21.11** | 21 | `~1.21.11` |
| `authme-fabric-mid` | **1.20.5 – 1.21.10** | 21 | `>=1.20.5 <1.21.11` |
| `authme-fabric-legacy` | **1.19.4 – 1.20.4** | 17 | `>=1.19.4 <1.20.5` |

> 1.16.5 – 1.19.3 are **not supported** — their pre-1.19 chat/`TextComponent` API and packet
> surfaces would need a separate `authme-fabric-legacy-old` module.

All three jars share:
- the same `authme-core` (`io.github.authme.fabric.*` packages), bundled as a Fabric **jar-in-jar**,
- the same bundled libraries (MySQL / MariaDB / PostgreSQL / SQLite JDBC, BouncyCastle, SnakeYAML),
- the same config file format and config directory (`<server>/config/authme/`).

So the **accounts database and config are 100% cross-version compatible** — you can switch jars when
upgrading your server without migrating data.

### Why the split?
Verified with `javap` against each target MC version's merged Mojmap jar:
- `CommandSourceStack.hasPermission(int)` → `PermissionSet` only in **1.21.11**
- `ResourceLocation.location()` → `Identifier.identifier()` only in **1.21.11**
- `ServerPlayer.level()` covariantly returns `ServerLevel` from 1.21.10; in 1.20.4 you need `serverLevel()`
- 1.20.4's `teleportTo(ServerLevel, …)` takes `Set<RelativeMovement>` and no trailing boolean; 1.21.x uses `Set<Relative>` + boolean
- 1.20.4's `UseItemCallback.interact` returns `InteractionResultHolder<ItemStack>`; 1.21.x returns `InteractionResult`

---

## Databases — and the "shared with Spigot AuthMe" trick

Supported backends (`DataSource.backend` in `config.yml`):

| Backend | Status | Notes |
|---|---|---|
| **MySQL** | ✅ | Creates the *exact* AuthMe table schema (configurable column names, `MEDIUMINT(8) UNSIGNED AUTO_INCREMENT`, `password ascii_bin`, `isLogged`/`hasSession`/`regdate`/`totp`/`premiumUUID`, …) |
| **MariaDB** | ✅ | Same schema, MariaDB JDBC driver |
| **PostgreSQL** | ✅ | AuthMe-shape schema with PG type mappings (`SERIAL`, `DOUBLE PRECISION`, `REAL`, `COLLATE "C"` in place of MySQL `ascii_bin`) |
| **SQLite** | ✅ | Local file under `config/authme/`; bundled `sqlite-jdbc` driver |

**Sharing one account database with a Bukkit/Spigot AuthMe install:**
1. Configure the **same** MySQL/MariaDB/PostgreSQL connection (host, port, database, table, username, password) in both `config.yml` files.
2. Use the **same** column names — the defaults already match upstream AuthMe (`username`, `realname`, `password`, `ip`, `lastlogin`, `regdate`, `isLogged`, `hasSession`, `totp`, `premiumUUID`, …).
3. Use the **same** `settings.security.passwordHash` (default `SHA256`).
4. The two servers can now read/write the same account rows; hashes are byte-identical, so a player registered on the Spigot side can log in on the Fabric side, and vice versa.

> ✅ Default config (`mySQLColumnSalt: ''`) matches upstream SHA256 (salt embedded in the hash).
> If you use a separate-salt algorithm (`SALTEDSHA256/512`, `SALTED2MD5`), set `mySQLColumnSalt` to the same value your AuthMe uses.

`MySQLDataSource` also runs `ALTER TABLE … ADD COLUMN` for any missing AuthMe column on startup, so pointing this port at a database created by the original plugin will not break it.

### Account converters
`/authme converter list` and `/authme converter <id> [arg]`:
- `sqliteToSql <path>` — copy all accounts from an AuthMe SQLite file into your configured SQL backend (**implemented**)
- `authplus`, `librelogin`, `limboauth`, `nlogin`, `openlogin`, `tiauth`, `nexauth`, `mysqlToSqlite` — listed as **stubs** pending schema-specific readers

---

## Requirements

| Component | Required version |
|---|---|
| Minecraft | 1.19.4 – 1.21.11 |
| Fabric Loader | ≥ 0.16.0 (built against 0.19.3) |
| Fabric API | any (built against the per-module pinned version) |
| Java | 21 for `authme-fabric` / `-mid`, 17 for `-legacy` |
| Optional proxy | `authme-velocity` or `authme-bungee` for premium bypass when behind an offline-mode proxy |

There are **no external plugin/runtime dependencies** at runtime — JDBC drivers, BouncyCastle and SnakeYAML are all bundled as Fabric jar-in-jar inside each module's jar.

---

## Build

Requires JDK 21 and internet access (Loom downloads Minecraft + Mojmap mappings on first run):

```bash
./gradlew clean build
```

Produces three jars:
- `authme-fabric/build/libs/authme-fabric-6.0.1-SNAPSHOT.jar`
- `authme-fabric-mid/build/libs/authme-fabric-mid-6.0.1-SNAPSHOT.jar`
- `authme-fabric-legacy/build/libs/authme-fabric-legacy-6.0.1-SNAPSHOT.jar`

(Plus matching `-sources.jar` for each.)

To build only one module: `./gradlew :authme-fabric-mid:build` etc.

---

## Install & configure

1. Pick the jar matching your MC version (see the coverage matrix).
2. Drop it into your server's `mods/` folder along with Fabric API.
3. Start the server once — this generates `config/authme/config.yml` and `config/authme/messages.yml`.
4. Stop the server and edit `config.yml`:
   - `DataSource.backend` — `SQLITE` (default) or `MYSQL` / `MARIADB` / `POSTGRESQL`
   - For SQL backends: `mySQLHost`, `mySQLPort`, `mySQLDatabase`, `mySQLTablename`, credentials, etc. **Match these to your existing AuthMe config to share accounts.**
   - `settings.security.passwordHash` (default `SHA256`) — use the same one as your existing AuthMe
   - `Settings.restrictUnauthenticated.allowCommands` — commands usable before login
   - `settings.session.enabled` / `timeout` — session login
   - `Security.captcha.*`, `Security.tempban.*` — brute-force protection
5. Restart. Done.

### Key config keys (compatible with AuthMe's `config.yml`)

```yaml
DataSource:
  backend: MYSQL
  mySQLHost: 127.0.0.1
  mySQLPort: 3306
  mySQLDatabase: authme
  mySQLTablename: authme
  mySQLUsername: authme
  mySQLPassword: '...'
  # Keep these column names identical to your existing AuthMe config:
  mySQLColumnName: username
  mySQLColumnPassword: password
  mySQLColumnSalt: ''          # '' for SHA256 (salt embedded); set for salted algorithms
  mySQLColumnIp: ip
  mySQLColumnLastLogin: lastlogin
  mySQLColumnRegisterDate: regdate
  mySQLColumnLogged: isLogged
  mySQLColumnHasSession: hasSession
  mySQLtotpKey: totp
  mySQLColumnPremiumUUID: premiumUUID

settings:
  security:
    passwordHash: SHA256       # the SAME value your Spigot AuthMe uses
    minPasswordLength: 5
    passwordMaxLength: 30
    # legacyHashes: [SHA1]    # optional fallback / auto-rehash migration
  session:
    enabled: false
    timeout: 60
```

---

## Commands (player)

| Command | Alias | Purpose |
|---|---|---|
| `/login <password>` | `/l` | Log in |
| `/register <pw> <pw>` | `/reg` | Register |
| `/changepassword <old> <new>` | `/changepass` | Change password (must be logged in) |
| `/logout` | — | Log out |
| `/unregister <password>` | — | Delete your account |
| `/captcha <code>` | — | Solve captcha |
| `/2fa <code>` | `/totp` | Verify 2FA code |
| `/2fa add` | — | Enable 2FA (prints secret + otpauth URI) |
| `/2fa remove <code>` | — | Disable 2FA |
| `/email add <email> <email>` | — | Add an email |
| `/email show` | — | Show email |
| `/premium` | — | Enable premium (Mojang) bypass for this account |
| `/freemium` | — | Disable premium bypass for this account |

---

## Permissions

- Player commands: open to all (AuthMe enforces authentication state itself)
- Admin commands (`/authme ...`): gated by the server's op-level permission
  - on `authme-fabric` (1.21.11) — `PermissionSet.ALL_PERMISSIONS`
  - on `-mid` / `-legacy` — `CommandSourceStack.hasPermission(3)` (op level ≥ 3)

---

## How it protects unauthenticated players

| Action | Mech |
|---|---|
| Walking / falling out of the join spot | Per-tick teleport-back to the frozen join location (cancels delta movement) |
| Sending a chat message | `ServerMessageEvents.ALLOW_CHAT_MESSAGE` returns false |
| Left / right click on block or entity; using an item | `AttackBlockCallback` / `UseBlockCallback` / `UseEntityCallback` / `AttackEntityCallback` / `UseItemCallback` return `FAIL` |
| Taking damage | `ServerLivingEntityEvents.ALLOW_DAMAGE` returns false |
| Clicking inside an inventory | `ContainerClickMixin` cancels `ServerGamePacketListenerImpl#handleContainerClick` at HEAD |
| Running a disallowed command | `CommandDispatcherMixin` cancels `CommandDispatcher#execute(...)` at HEAD unless the command root is in `allowCommands` |
| Joining with a name that's registered to a premium account | (when `enablePremium: true`) Skips password login, learns the verified Mojang UUID from the proxy or `premiumUUID` column |
| Bot-style connection spam | `AntiBotManager` blocks new joins once a configured rate threshold is exceeded |

### What is NOT ported from upstream
- **Pre-join dialog UI** (paper-only, complex client-protocol work)
- **Email recovery / verification flow** (email sending is not bundled)
- **Country whitelist/blacklist** (MaxMind GeoIP viewer)
- **Account importers for Auth+/LibreLogin/LimboAuth/nLogin/OpeNLogin/tiAuth/NexAuth** (stubs only)
- **`/authme backup`** (command exists but does not yet write a `.tar` of the database)
- 1.16.5 – 1.19.3 support

---

## Architecture

```
authme-core/                   # pure Java 17 — no Minecraft dependency
  src/main/java/io/github/authme/fabric/
    security/                   # hashing (SHA256/BCrypt/PBKDF2/Argon2/…)
    datasource/                 # MySQL/MariaDB/PostgreSQL/SQLite + connection pool
    converter/                  # account importers (sqliteToSql live, others stubbed)
    totp/                       # RFC 6238 TOTP client
    config/                     # YAML config + messages (SnakeYAML)
    antibot/                    # rate-limit
    auth/                       # PlayerSession (pure data, no ServerPlayer ref)
    util/Log.java               # pluggable Log.Sink (log4j keeps in platform module)
authme-fabric/                 # 1.21.11, Java 21, Identifier + PermissionSet
authme-fabric-mid/             # 1.20.5–1.21.10, Java 21, ResourceLocation + hasPermission
authme-fabric-legacy/          # 1.19.4–1.20.4, Java 17, RelativeMovement
                               # each platform module has: AuthMe, AuthManager,
                               # AuthMeFabric, AuthMeCommands, AuthMeEvents,
                               # MinecraftText, ContainerClickMixin, CommandDispatcherMixin
```

Each platform module bundles `authme-core` and the bundled libraries (MySQL/MariaDB/PostgreSQL/SQLite
JDBC, BouncyCastle, SnakeYAML) as Fabric **jar-in-jar** — no user-side runtime dependencies.

---

## License

```
AuthMe Fabric
Copyright (C) since 2026 AuthMe Fabric port contributors
Copyright (C) since 2013 AuthMe-Team (upstream AuthMeReloaded)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
```

See [`LICENSE`](LICENSE) for the full GPLv3 text.

Upstream: [`AuthMe/AuthMeReloaded`](https://github.com/AuthMe/AuthMeReloaded) — please go star
the original project, without which this port would not exist.

---

## Acknowledgements

- **AuthMe-Team** — upstream authors and ongoing maintainers of AuthMeReloaded.
- **FabricMC** — Loom, Fabric Loader and Fabric API.
- **BouncyCastle** — BCrypt / PBKDF2 / Argon2 implementation.
- **xerial** — `sqlite-jdbc` driver.
- All the upstream AuthMe translators and contributors.

## Issues / contributing

This is a derivative port; bugs introduced by the port are this project's responsibility — please
file them on [this repo's issue tracker](issues). For upstream AuthMe behaviour / hashing questions,
the [upstream issue tracker](https://github.com/AuthMe/AuthMeReloaded/issues) is still the canonical
place.