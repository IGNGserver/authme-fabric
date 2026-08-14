package io.github.authme.fabric;

import io.github.authme.fabric.config.AuthMeConfig;
import io.github.authme.fabric.config.EventCommands;
import io.github.authme.fabric.config.GeoIpPolicy;
import io.github.authme.fabric.config.Messages;
import io.github.authme.fabric.config.RegisterSecondaryArgument;
import io.github.authme.fabric.config.RegistrationType;
import io.github.authme.fabric.config.WelcomeMessage;
import io.github.authme.fabric.datasource.PlayerAuth;
import io.github.authme.fabric.util.PurgeFileCleaner;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

/** Verifies compatibility paths used by AuthMeReloaded's older config layout. */
public final class ConfigSelfTest {

    private ConfigSelfTest() { }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("authme-config-selftest-");
        Path defaultsDir = Files.createTempDirectory("authme-config-defaults-");
        AuthMeConfig defaults = new AuthMeConfig(defaultsDir);
        require(defaults.load() && defaults.registrationType() == RegistrationType.PASSWORD
                && defaults.registrationSecondArgument() == RegisterSecondaryArgument.CONFIRMATION
                && Files.exists(defaults.welcomeFile()) && !WelcomeMessage.load(defaults).isEmpty(),
            "default config or welcome message resource did not load");
        Files.writeString(dir.resolve("config.yml"), """
            DataSource:
              backend: SQLITE
            settings:
              messagesLanguage: en
              delayJoinMessage: true
              customJoinMessage: '&a{PLAYERNAME}'
              removeUnloggedLeaveMessage: true
              removeJoinMessage: true
              removeLeaveMessage: true
              registration:
                type: PASSWORD
                secondArg: NONE
                dialog:
                  postJoin:
                    enable: true
                  showBody: false
              sessions:
                enabled: true
                timeout: 17
                sessionExpireOnIpChange: true
              restrictions:
                allowMovement: true
                maxRegPerIp: 2
                maxLoginPerIp: 3
                maxJoinPerIp: 4
                AllowRestrictedUser: true
                AllowedRestrictedUser:
                  - playerone;127.0.0.*
                enablePasswordVerifier: false
                allowedNicknameCharacters: '^[A-Za-z0-9_]+$'
                allowedPasswordCharacters: '^[A-Za-z0-9]+$'
                ProtectInventoryBeforeLogIn: false
            Email:
              mailSMTP: localhost
              mailPort: 2525
              mailAccount: authme@example.test
              delayRecall: 2
            BackupSystem:
              ActivateBackup: true
              OnServerStart: true
              OnServerStop: true
            Purge:
              useAutoPurge: true
              daysBeforeRemovePlayer: 42
            """);
        AuthMeConfig config = new AuthMeConfig(dir);
        require(config.load(), "legacy config did not load");
        require(config.sessionEnabled() && config.sessionTimeoutMinutes() == 17 && config.sessionOnlyIp(),
            "legacy session keys were not mapped");
        require(config.maxRegistrationsPerIp() == 2 && config.maxLoginPerIp() == 3 && config.maxJoinPerIp() == 4,
            "legacy restriction limits were not mapped");
        require(config.allowRestrictedUsers() && config.allowedRestrictedUsers().size() == 1
                && !config.requirePasswordConfirmation(),
            "legacy restricted-user/password-verifier keys were not mapped");
        require(config.allowMovement() && !config.protectInventoryBeforeLogin(),
            "legacy restriction booleans were not mapped");
        require("en".equals(config.messagesLanguage()) && config.dialogPostJoinEnabled()
                && !config.dialogShowBody(), "dialog/message compatibility keys were not mapped");
        require(config.registrationType() == RegistrationType.PASSWORD
                && config.registrationSecondArgument() == RegisterSecondaryArgument.NONE
                && !config.requirePasswordConfirmation(), "registration enum settings were not mapped");
        require(config.emailEnabled() && config.emailPort() == 2525,
            "legacy mail keys were not mapped");
        require(config.emailRecoveryTimeoutSeconds() == 120,
            "legacy mail recovery timeout was not converted from minutes");
        require(config.backupEnabled() && config.backupOnStart() && config.backupOnStop()
                && config.purgeEnabled() && config.purgeDays() == 42,
            "legacy backup/purge keys were not mapped");
        require(config.delayJoinMessage() && "&a{PLAYERNAME}".equals(config.customJoinMessage())
                && config.removeUnloggedLeaveMessage() && config.removeJoinMessage()
                && config.removeLeaveMessage(), "join/leave message settings were not mapped");

        Files.writeString(dir.resolve("config.yml"), """
            settings:
              registration:
                enableEmailRegistrationSystem: true
                doubleEmailCheck: true
            """);
        require(config.load() && config.registrationType() == RegistrationType.EMAIL
                && config.registrationSecondArgument() == RegisterSecondaryArgument.CONFIRMATION,
            "legacy email registration settings were not migrated");

        Files.writeString(dir.resolve("messages.yml"), """
            login:
              success: '&aNested custom login'
            """);
        Files.writeString(dir.resolve("messages_zh_cn.yml"), """
            login:
              wrong: '&cLocalized wrong password'
            """);
        Messages messages = new Messages(dir, "zh-CN");
        require(messages.load()
                && "&aNested custom login".equals(messages.get("login.success"))
                && "&cLocalized wrong password".equals(messages.get("login.wrong")),
            "nested AuthMe messages or locale override was not loaded");
        int addedMessages = messages.addMissingDefaults();
        require(addedMessages > 0
                && Files.readString(dir.resolve("messages.yml")).contains("admin.messagesUpdated")
                && messages.has("admin.messagesUpdated"),
            "missing AuthMe messages were not appended without overwriting custom values");

        Path mapping = dir.resolve("geoip-countries.csv");
        Files.writeString(mapping, "127.0.0.0/8,LOCALHOST\n10.0.0.0/8,ZZ\n");
        Files.writeString(dir.resolve("config.yml"), """
            Protection:
              enableProtection: true
              geoIpDatabase:
                enabled: true
                file: geoip-countries.csv
              countries: [LOCALHOST]
              countriesBlacklist: []
            """);
        require(config.load(), "geoip config did not load");
        GeoIpPolicy geoIp = new GeoIpPolicy(config);
        require(geoIp.mappingAvailable() && geoIp.isAllowed("127.0.0.1")
                && !geoIp.isAllowed("10.1.2.3"), "GeoIP CIDR whitelist was not enforced");

        Path mmdb = dir.resolve("country.mmdb");
        Files.write(mmdb, syntheticCountryDatabase());
        Files.writeString(dir.resolve("config.yml"), """
            Protection:
              enableProtection: true
              geoIpDatabase:
                enabled: true
                file: country.mmdb
              countries: [US]
              countriesBlacklist: []
            """);
        require(config.load(), "mmdb config did not load");
        GeoIpPolicy mmdbPolicy = new GeoIpPolicy(config);
        require(mmdbPolicy.mappingAvailable() && "US".equals(mmdbPolicy.countryCode("8.8.8.8"))
                && mmdbPolicy.isAllowed("8.8.8.8") && !mmdbPolicy.isAllowed("200.1.2.3"),
            "MaxMind country database lookup was not enforced");

        UUID uuid = UUID.randomUUID();
        Files.createDirectories(dir.resolve("world/playerdata"));
        Files.createDirectories(dir.resolve("world/players"));
        Files.createDirectories(dir.resolve("plugins/Essentials/userdata"));
        Files.createDirectories(dir.resolve("plugins/LimitedCreative/inventories"));
        Files.createDirectories(dir.resolve("plugins/AntiXRayData/PlayerData"));
        for (Path file : List.of(
            dir.resolve("world/playerdata/" + uuid + ".dat"),
            dir.resolve("world/players/" + uuid + ".dat"),
            dir.resolve("plugins/Essentials/userdata/" + uuid + ".yml"),
            dir.resolve("plugins/LimitedCreative/inventories/playerone.yml"),
            dir.resolve("plugins/LimitedCreative/inventories/playerone_creative.yml"),
            dir.resolve("plugins/AntiXRayData/PlayerData/playerone"))) Files.writeString(file, "test");
        Files.writeString(dir.resolve("config.yml"), """
            Purge:
              removePlayerDat: true
              removeEssentialsFile: true
              defaultWorld: world
              removeLimitedCreativesInventories: true
              removeAntiXRayFile: true
            """);
        require(config.load(), "purge config did not load");
        PlayerAuth purgeAccount = PlayerAuth.builder().name("playerone").realName("PlayerOne").uuid(uuid).build();
        int deleted = PurgeFileCleaner.clean(dir, config, List.of(purgeAccount), true);
        require(deleted == 6
                && !Files.exists(dir.resolve("world/playerdata/" + uuid + ".dat"))
                && !Files.exists(dir.resolve("plugins/LimitedCreative/inventories/playerone_creative.yml")),
            "purge file cleanup was not complete or safe");

        Files.writeString(dir.resolve("commands.yml"), """
            onLogin:
              welcome:
                command: 'say %p'
                executor: CONSOLE
                delay: 20
                ifNumberOfAccountsAtLeast: 2
            """);
        EventCommands commands = new EventCommands(dir);
        require(commands.load(), "commands.yml did not load");
        EventCommands.ConfiguredCommand command = commands.get("onLogin").get(0);
        require(command.delayTicks() == 20 && command.accountsAtLeast() == 2
            && command.executor() == EventCommands.Executor.CONSOLE,
            "event command options were not parsed");
        System.out.println("AuthMe config/event-command self-test passed.");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    /** Creates a tiny valid MaxMind DB with US for the left half and ZZ for the right half. */
    private static byte[] syntheticCountryDatabase() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int leftPointer = 1 + 16;
        byte[] us = countryRecord("US");
        int rightPointer = leftPointer + us.length;
        write24(out, leftPointer);
        write24(out, rightPointer);
        out.write(new byte[16]);
        out.write(us);
        out.write(countryRecord("ZZ"));
        out.write(new byte[] {
            (byte) 0xab, (byte) 0xcd, (byte) 0xef, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'
        });
        out.write(0xe3); // map with node_count, record_size and ip_version
        writeString(out, "node_count");
        out.write(0xc1); out.write(1); // unsigned 32-bit integer
        writeString(out, "record_size");
        out.write(0xa1); out.write(24); // unsigned 16-bit integer
        writeString(out, "ip_version");
        out.write(0xa1); out.write(4);
        return out.toByteArray();
    }

    private static byte[] countryRecord(String code) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xe1); // one-pair map
        writeString(out, "country");
        out.write(0xe1);
        writeString(out, "iso_code");
        out.write(0x42);
        out.write(code.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return out.toByteArray();
    }

    private static void writeString(ByteArrayOutputStream out, String value) throws Exception {
        byte[] bytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        out.write(0x40 | bytes.length);
        out.write(bytes);
    }

    private static void write24(ByteArrayOutputStream out, int value) {
        out.write((value >>> 16) & 0xff);
        out.write((value >>> 8) & 0xff);
        out.write(value & 0xff);
    }
}
