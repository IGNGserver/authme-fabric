package io.github.authme.platform;

import io.github.authme.fabric.datasource.DataSource;
import io.github.authme.fabric.totp.TotpProvider;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

/** Smoke test for the platform-neutral account service using its isolated SQLite database. */
public final class PlatformCoreSelfTest {

    private PlatformCoreSelfTest() { }

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("authme-platform-core-");
        PlatformAuthService service = PlatformAuthService.start(directory);
        try {
            require(service.isValidUsername("Paper_Player"), "valid username was rejected");
            require(!service.isValidUsername("bad-name"), "invalid username was accepted");
            require(!service.isValidPasswordInput("密码"), "non-ASCII password bypassed the configured policy");
            require(service.isValidEmailInput("paper@example.com")
                    && !service.isValidEmailInput("not-an-email"), "email policy boundary was not enforced");
            require(service.register("Paper_Player", "secret-password", "secret-password", "127.0.0.1")
                    == PlatformAuthService.AccountResult.SUCCESS, "registration failed");
            require(service.register("paper_player", "secret-password", "127.0.0.1")
                    == PlatformAuthService.AccountResult.ALREADY_REGISTERED, "duplicate registration accepted");
            require(service.register("Alt_Player", "secret-password", "secret-password", "127.0.0.1", true)
                    == PlatformAuthService.AccountResult.SUCCESS,
                "explicit allow-multiple-accounts registration failed");
            require(service.register("Third_Player", "secret-password", "secret-password", "127.0.0.1")
                    == PlatformAuthService.AccountResult.REGISTRATION_LIMIT,
                "per-IP registration limit was bypassed without permission");
            require(service.login("paper_player", "secret-password", "127.0.0.1", false)
                    == PlatformAuthService.AccountResult.NOT_REGISTERED,
                "case-mismatched account login was accepted");
            require(service.login("Paper_Player", "wrong-password", "127.0.0.1", false)
                    == PlatformAuthService.AccountResult.WRONG_PASSWORD, "wrong password accepted");
            require(service.login("Paper_Player", "secret-password", "127.0.0.1", false)
                    == PlatformAuthService.AccountResult.RATE_LIMITED, "login retry throttle was bypassed");
            Thread.sleep(550L);
            require(service.login("Paper_Player", "secret-password", "127.0.0.1", false)
                    == PlatformAuthService.AccountResult.SUCCESS, "login failed");
            long failureCheckAt = System.currentTimeMillis();
            require(service.dataSource().readFailureState("auth|paper_player|127.0.0.1",
                    failureCheckAt, 60_000L).attempts() == 0,
                "successful login did not clear its account/source failure bucket");
            require(service.dataSource().readFailureState("ip|127.0.0.1",
                    failureCheckAt, 60_000L).attempts() >= 1,
                "successful login incorrectly cleared the shared source failure bucket");
            DataSource.LookupResult lookup = service.lookup("paper_player");
            require(lookup.successful() && lookup.auth() != null && lookup.auth().isLogged(),
                "login state was not persisted");
            require(service.changePassword("paper_player", "secret-password", "new-password")
                    == PlatformAuthService.AccountResult.SUCCESS, "password change failed");
            require(service.changePassword("paper_player", "new-password", "password")
                    == PlatformAuthService.AccountResult.UNSAFE_PASSWORD,
                "unsafe password was accepted during password change");
            require(service.logout("paper_player") == PlatformAuthService.AccountResult.SUCCESS,
                "logout failed");

            // Exercise the configured CAPTCHA boundary after a fresh reload.
            Path configFile = directory.resolve("config.yml");
            String config = Files.readString(configFile, StandardCharsets.UTF_8)
                .replace("useCaptcha: false", "useCaptcha: true")
                .replace("maxLoginTry: 5", "maxLoginTry: 1")
                .replace("maxLoginPerIp: 0", "maxLoginPerIp: 1")
                .replace("AllowRestrictedUser: false", "AllowRestrictedUser: true")
                .replace("AllowedRestrictedUser: []", "AllowedRestrictedUser: ['Paper_Player;127.0.0.*']")
                .replace("enabled: false\n        # Session timeout", "enabled: true\n        # Session timeout");
            Files.writeString(configFile, config, StandardCharsets.UTF_8);
            service.reload();
            require(service.isRestrictedAddressAllowed("Paper_Player", "127.0.0.1"),
                "allowed restricted-user address was rejected");
            require(!service.isRestrictedAddressAllowed("Paper_Player", "10.0.0.1"),
                "restricted-user address rule was bypassed");
            require(service.login("Paper_Player", "wrong-password", "127.0.0.1", false)
                    == PlatformAuthService.AccountResult.CAPTCHA_REQUIRED,
                "captcha was not required after the configured threshold");
            String captcha = service.captchaChallenge("paper_player", "127.0.0.1");
            require(!captcha.isBlank(), "captcha challenge was not generated");
            require(service.verifyCaptcha("paper_player", "127.0.0.1", captcha)
                    == PlatformAuthService.AccountResult.SUCCESS, "captcha verification failed");
            PlatformAuthService.AccountResult postCaptchaLogin =
                service.login("Paper_Player", "new-password", "127.0.0.1", false);
            require(postCaptchaLogin == PlatformAuthService.AccountResult.SUCCESS,
                "post-CAPTCHA login failed: " + postCaptchaLogin);
            PlatformAuthService.AccountResult limitedLogin =
                service.login("Alt_Player", "secret-password", "127.0.0.1", false);
            require(limitedLogin == PlatformAuthService.AccountResult.LOGIN_LIMIT,
                "per-IP login limit was bypassed");
            require(service.logout("Paper_Player") == PlatformAuthService.AccountResult.SUCCESS,
                "login-limit setup logout failed");

            // Email mutations must stay bounded and must not require an SMTP connection when
            // verification is explicitly disabled.  The runtime adapters still gate these calls
            // on an authenticated player session.
            String emailConfig = Files.readString(configFile, StandardCharsets.UTF_8)
                .replace("Email:\n    enabled: false", "Email:\n    enabled: true");
            Files.writeString(configFile, emailConfig, StandardCharsets.UTF_8);
            service.reload();
            require(service.addEmail("paper_player", "paper@example.com", "wrong@example.com")
                    == PlatformAuthService.AccountResult.EMAIL_MISMATCH,
                "email confirmation mismatch was accepted");
            require(service.addEmail("paper_player", "paper@example.com", "paper@example.com")
                    == PlatformAuthService.AccountResult.EMAIL_ADDED, "email add failed");
            require("paper@example.com".equals(service.email("paper_player")),
                "email was not persisted");
            require(service.changeEmail("paper_player", "paper@example.com", "new@example.com")
                    == PlatformAuthService.AccountResult.EMAIL_CHANGED, "email change failed");

            require(service.dataSource().setLoginState("paper_player", "127.0.0.1",
                    System.currentTimeMillis(), true), "could not create session state");
            require(service.hasValidSession("Paper_Player", "127.0.0.1"),
                "read-only valid-session check rejected the bound session");
            require(service.sessionLogin("Paper_Player", "unknown")
                    == PlatformAuthService.AccountResult.SESSION_INVALID,
                "an unbound session was accepted");
            require(service.sessionLogin("Paper_Player", "127.0.0.1")
                    == PlatformAuthService.AccountResult.SUCCESS, "session login failed");

            long staleConnection = service.beginConnection("paper_player");
            require(staleConnection > 0L && service.isCurrentConnection("paper_player", staleConnection),
                "connection generation was not opened");
            require(service.dataSource().setLoginFlags("paper_player", true, true),
                "could not prepare connection race state");
            long currentConnection = service.beginConnection("paper_player");
            require(currentConnection != staleConnection
                    && service.isCurrentConnection("paper_player", currentConnection),
                "connection generation did not advance");
            require(service.logoutIfConnection("paper_player", staleConnection)
                    == PlatformAuthService.AccountResult.SUCCESS,
                "stale connection callback was rejected instead of becoming a no-op");
            require(service.lookup("paper_player").auth().isLogged(),
                "stale connection callback logged out the replacement connection");
            require(service.logoutIfConnection("paper_player", currentConnection)
                    == PlatformAuthService.AccountResult.SUCCESS,
                "current connection logout failed");
            require(service.sessionLoginIfConnection("paper_player", "127.0.0.1", staleConnection)
                    == PlatformAuthService.AccountResult.STALE_CONNECTION,
                "stale session callback was accepted");
            require(service.premiumLoginIfConnection("paper_player", java.util.UUID.randomUUID(),
                    true, "127.0.0.1", staleConnection)
                    == PlatformAuthService.AccountResult.STALE_CONNECTION,
                "stale premium callback was accepted");

            long locationConnection = service.beginConnection("paper_player");
            long locationLogin = System.currentTimeMillis();
            require(service.dataSource().setLoginState("paper_player", "127.0.0.1", locationLogin, true),
                "could not prepare quit-location state");
            PlatformAuthService.AccountResult locationSession =
                service.sessionLogin("Paper_Player", "127.0.0.1");
            require(locationSession == PlatformAuthService.AccountResult.SUCCESS,
                "could not acquire the fenced quit-location lease: " + locationSession);
            require(service.disconnectIfConnection("paper_player", locationConnection,
                    12.5, 65.0, -3.25, 90.0f, 15.0f, "world", true)
                    == PlatformAuthService.AccountResult.SUCCESS,
                "current connection quit state failed");
            require(!service.lookup("paper_player").auth().isLogged()
                    && Math.abs(service.lookup("paper_player").auth().getLocX() - 12.5) < 0.001,
                "quit location or login flags were not persisted atomically");

            PlatformAuthService.TotpResult setup = service.enableTotp("paper_player");
            require(setup.result() == PlatformAuthService.AccountResult.SUCCESS
                    && service.lookup("paper_player").auth().getTotpKey() == null,
                "TOTP setup was persisted before confirmation");
            require(service.confirmTotp("paper_player", setup.secret(), "000000")
                    == PlatformAuthService.AccountResult.WRONG_TOTP,
                "invalid TOTP setup confirmation was accepted");
            require(service.dataSource().updateTotpKey("paper_player", TotpProvider.generateSecret()),
                "could not set test TOTP key");
            require(service.dataSource().setLoginState("paper_player", "127.0.0.1",
                    System.currentTimeMillis(), true), "could not prepare TOTP session state");
            require(service.sessionLogin("Paper_Player", "127.0.0.1")
                    == PlatformAuthService.AccountResult.TOTP_REQUIRED,
                "TOTP session login bypassed the second factor");
            require(service.login("Paper_Player", "new-password", "127.0.0.1", false)
                    == PlatformAuthService.AccountResult.TOTP_REQUIRED, "TOTP login requirement was bypassed");
            require(service.verifyTotp("paper_player", "000000", "127.0.0.1", false)
                    == PlatformAuthService.AccountResult.WRONG_TOTP, "wrong TOTP code was accepted");
            require(service.dataSource().updateTotpKey("paper_player", null), "could not clear test TOTP key");
            require(service.unregister("paper_player", "new-password") == PlatformAuthService.AccountResult.SUCCESS,
                "unregister failed");
        } finally {
            service.close();
        }
        System.out.println("AuthMe platform core self-test passed.");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
