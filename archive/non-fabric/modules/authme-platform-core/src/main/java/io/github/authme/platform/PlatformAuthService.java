package io.github.authme.platform;

import io.github.authme.fabric.config.AuthMeConfig;
import io.github.authme.fabric.auth.EmailChallenge;
import io.github.authme.fabric.auth.EmailAddressPolicy;
import io.github.authme.fabric.config.RegisterSecondaryArgument;
import io.github.authme.fabric.config.RegistrationType;
import io.github.authme.fabric.datasource.CachingDataSource;
import io.github.authme.fabric.datasource.DataSource;
import io.github.authme.fabric.datasource.DataSourceType;
import io.github.authme.fabric.datasource.DbSettings;
import io.github.authme.fabric.datasource.MariaDBDataSource;
import io.github.authme.fabric.datasource.MySQLDataSource;
import io.github.authme.fabric.datasource.PlayerAuth;
import io.github.authme.fabric.datasource.PostgreSqlDataSource;
import io.github.authme.fabric.datasource.SQLiteDataSource;
import io.github.authme.fabric.security.HashedPassword;
import io.github.authme.fabric.security.PasswordSecurity;
import io.github.authme.fabric.security.RandomStringUtils;
import io.github.authme.fabric.mail.EmailSender;
import io.github.authme.fabric.totp.TotpProvider;

import java.nio.file.Path;
import java.sql.SQLException;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Platform-neutral account service for Bukkit-family adapters.
 *
 * <p>It deliberately contains no Bukkit, Paper, Folia or Fabric runtime types. Platform code
 * supplies scheduling and presentation, while this class owns the account boundary, hash
 * verification, database error semantics and per-account serialization.</p>
 */
public final class PlatformAuthService implements AutoCloseable {

    private static final int MAX_NAME_LENGTH = 16;
    private static final int MAX_PASSWORD_LENGTH = 256;
    private static final int MAX_IP_LENGTH = 64;
    private static final int MAX_LOCKS = 16_384;
    private static final int MAX_EMAIL_CHALLENGES = 8_192;
    private static final int MAX_CAPTCHAS = 8_192;
    private static final int LOCK_STRIPES = 2_048;
    private static final long MIN_RETRY_DELAY_MILLIS = 500L;

    private final Path configDirectory;
    // Fixed lock stripes keep memory bounded without evicting a lock that another
    // request may currently hold (evicting such a lock would reintroduce races).
    private final Object[] accountLockStripes = createLockStripes();
    private final Map<String, EmailChallenge> emailChallenges = new ConcurrentHashMap<>();
    private final Map<String, Long> recoveryLastSent = new ConcurrentHashMap<>();
    private final Map<String, CaptchaState> captchas = new ConcurrentHashMap<>();
    /** Short-lived proof that the player solved a registration/login CAPTCHA. */
    private final Map<String, Long> captchaPasses = new ConcurrentHashMap<>();
    /** Monotonic per-account connection generations used to ignore stale quit callbacks. */
    private final Map<String, Long> connectionEpochs = new ConcurrentHashMap<>();
    /** Database fencing version owned by this runtime's current authenticated connection. */
    private final Map<String, Long> loginLeases = new ConcurrentHashMap<>();
    private final AtomicLong connectionSequence = new AtomicLong();
    private volatile AuthMeConfig config;
    private volatile PasswordSecurity passwordSecurity;
    private volatile DataSource dataSource;
    private volatile Pattern nicknamePattern;
    private volatile Pattern passwordPattern;

    private PlatformAuthService(Path configDirectory) {
        this.configDirectory = configDirectory.toAbsolutePath().normalize();
    }

    public static PlatformAuthService start(Path configDirectory) throws Exception {
        PlatformAuthService service = new PlatformAuthService(configDirectory);
        service.reload();
        return service;
    }

    public synchronized void reload() throws Exception {
        AuthMeConfig nextConfig = new AuthMeConfig(configDirectory);
        if (!nextConfig.load()) throw new IllegalStateException("AuthMe config.yml could not be loaded");
        nextConfig.validateSecurityConfiguration();
        Pattern nextNicknamePattern = compileInputPattern(nextConfig.allowedNicknameCharacters(), "nickname");
        Pattern nextPasswordPattern = compileInputPattern(nextConfig.allowedPasswordCharacters(), "password");
        PasswordSecurity nextSecurity = new PasswordSecurity(nextConfig.passwordHash(), nextConfig.pbkdf2Rounds(),
            nextConfig.bcryptLog2Round(), nextConfig.doubleMD5SaltLength(), nextConfig.legacyHashes());
        DbSettings settings = nextConfig.toDbSettings();
        if (nextSecurity.getPrimaryMethod() == null) {
            throw new IllegalStateException("CUSTOM password hashing is not available in the platform service");
        }
        if (nextSecurity.hasSeparateSalt() && !settings.columns.hasSaltColumn()) {
            throw new IllegalStateException("Configured password hash requires a separate salt column");
        }

        DataSource nextDataSource = createDataSource(settings);
        if (!nextDataSource.ping()) {
            nextDataSource.close();
            throw new SQLException("AuthMe database health check failed");
        }
        if (nextConfig.dataSourceCaching()) {
            nextDataSource = new CachingDataSource(nextDataSource,
                nextConfig.cacheRefreshSeconds() * 1000L, nextConfig.cacheExpireMinutes() * 60_000L);
        }
        DataSource previous = dataSource;
        config = nextConfig;
        passwordSecurity = nextSecurity;
        nicknamePattern = nextNicknamePattern;
        passwordPattern = nextPasswordPattern;
        dataSource = nextDataSource;
        if (previous != null) previous.close();
    }

    public AuthMeConfig config() { return config; }
    public DataSource dataSource() { return dataSource; }

    /** Runs the operator-only MySQL/MariaDB column definition utility. */
    public DataSource.MySqlDefinitionResult mysqlDefinition(
        DataSource.MySqlDefinitionOperation operation, String column) {
        return dataSource.mysqlDefinition(operation, column);
    }

    /** Safe diagnostics used by the platform debug command; these methods do not expose secrets. */
    public boolean isValidUsername(String rawName) { return normalizeName(rawName) != null; }
    public boolean isValidPasswordInput(String password) { return validPassword(password); }
    public boolean isValidEmailInput(String email) { return email != null && validEmail(email.trim()); }

    /**
     * Read-only session check for connection-phase UI. Unlike {@link #sessionLogin}, this method
     * never writes login state, so a pre-join dialog cannot consume or manufacture a session.
     */
    public boolean hasValidSession(String rawName, String ip) {
        String name = normalizeName(rawName);
        String currentIp = normalizeIp(ip);
        if (name == null || !config.sessionEnabled() || "unknown".equals(currentIp)) return false;
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful() || lookup.auth() == null) return false;
            PlayerAuth auth = lookup.auth();
            if (!caseMatches(auth, rawName)) return false;
            long lastLogin = auth.getLastLogin() == null ? 0L : auth.getLastLogin();
            if (!auth.hasSession() || "unknown".equals(normalizeIp(auth.getLastIp()))
                || !currentIp.equals(normalizeIp(auth.getLastIp())) || lastLogin <= 0L
                || System.currentTimeMillis() < lastLogin
                || System.currentTimeMillis() - lastLogin > config.sessionTimeoutMinutes() * 60_000L
                || (auth.getTotpKey() != null && !auth.getTotpKey().isBlank())) return false;
            return loginLimitAllowsSnapshot(auth, currentIp);
        }
    }

    /**
     * Applies AuthMe's optional {@code AllowedRestrictedUser} rules. A username with no rule is
     * unrestricted; once a rule exists, at least one of that username's IP patterns must match.
     */
    public boolean isRestrictedAddressAllowed(String rawName, String ip) {
        if (!config.allowRestrictedUsers()) return true;
        if (rawName == null || rawName.isBlank()) return false;
        String name = rawName.trim();
        String address = normalizeIp(ip);
        boolean hasRule = false;
        for (String rawRule : config.allowedRestrictedUsers()) {
            if (rawRule == null || rawRule.length() > 2048) continue;
            String[] parts = rawRule.split(";", 2);
            if (parts.length != 2 || !name.equalsIgnoreCase(parts[0].trim())) continue;
            hasRule = true;
            if (matchesRestrictedPattern(address, parts[1].trim())) return true;
        }
        return !hasRule;
    }

    /** Opens a connection generation for a live platform player. */
    public long beginConnection(String rawName) {
        String name = normalizeName(rawName);
        if (name == null) return 0L;
        synchronized (lockFor(name)) {
            long next = connectionSequence.updateAndGet(previous ->
                previous == Long.MAX_VALUE ? 1L : previous + 1L);
            if (connectionEpochs.size() >= MAX_LOCKS && !connectionEpochs.containsKey(name)) {
                connectionEpochs.keySet().stream().findFirst().ifPresent(connectionEpochs::remove);
            }
            connectionEpochs.put(name, next);
            return next;
        }
    }

    /** Returns whether a callback still belongs to the currently connected player. */
    public boolean isCurrentConnection(String rawName, long token) {
        String name = normalizeName(rawName);
        if (name == null || token <= 0L) return false;
        synchronized (lockFor(name)) {
            return isCurrentConnectionLocked(name, token);
        }
    }

    /**
     * Clears online state only for the connection generation that is quitting. A delayed quit
     * from an older connection is a successful no-op and cannot log out a rapid reconnect.
     */
    public AccountResult logoutIfConnection(String rawName, long token) {
        String name = normalizeName(rawName);
        if (name == null || token <= 0L) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, token)) return AccountResult.SUCCESS;
            DataSource.CheckResult available = dataSource.checkAuthAvailable(name);
            if (!available.successful()) return AccountResult.DATABASE_ERROR;
            if (!available.available()) return AccountResult.NOT_REGISTERED;
            Long ownedVersion = loginLeases.get(name);
            if (ownedVersion == null || ownedVersion <= 0L) return AccountResult.SUCCESS;
            boolean cleared = dataSource.clearLoginIfLastLogin(name, ownedVersion);
            if (cleared) loginLeases.remove(name, ownedVersion);
            return cleared ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
        }
    }

    /**
     * Persists a quit location only for the live connection that owns the account's login
     * timestamp. A delayed quit from an older connection is a safe no-op.
     */
    public AccountResult disconnectIfConnection(String rawName, long token,
                                                double x, double y, double z,
                                                float yaw, float pitch, String world,
                                                boolean saveLocation) {
        String name = normalizeName(rawName);
        if (name == null || token <= 0L) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, token)) return AccountResult.SUCCESS;
            Long ownedVersion = loginLeases.get(name);
            if (ownedVersion == null || ownedVersion <= 0L) return AccountResult.SUCCESS;
            boolean persisted = dataSource.persistDisconnectIfLastLogin(name, ownedVersion,
                System.currentTimeMillis(), x, y, z, yaw, pitch, world, saveLocation,
                config.sessionEnabled());
            if (persisted) loginLeases.remove(name, ownedVersion);
            return persisted ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
        }
    }

    /**
     * Backwards-compatible password registration entry point for callers that already validated
     * the command arguments. Platform command adapters should use the four-argument overload so
     * the AuthMe registration type and second-argument policy are enforced here as well.
     */
    public AccountResult register(String rawName, String password, String ip) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        return registerPasswordAccount(name, rawName.trim(), password, null, ip, true, false);
    }

    /** Processes the complete AuthMe-compatible /register argument contract. */
    public AccountResult register(String rawName, String first, String second, String ip) {
        return register(rawName, first, second, ip, false);
    }

    /**
     * Processes registration while optionally bypassing the per-IP registration limit for a
     * caller that has the explicit AuthMe allow-multiple-accounts permission.
     */
    public AccountResult register(String rawName, String first, String second, String ip,
                                  boolean bypassIpLimit) {
        String name = normalizeName(rawName);
        if (name == null || !config.registrationEnabled()) return name == null
            ? AccountResult.INVALID_INPUT : AccountResult.REGISTRATION_DISABLED;
        if (config.registrationType() == RegistrationType.EMAIL) {
            String email = first == null ? "" : first.trim();
            if (!validEmail(email)) return AccountResult.EMAIL_INVALID;
            if (config.registrationSecondArgument() != RegisterSecondaryArgument.NONE
                && (second == null || !email.equalsIgnoreCase(second.trim()))) {
                return AccountResult.EMAIL_MISMATCH;
            }
            return registerEmailAccount(name, rawName.trim(), email, ip, bypassIpLimit);
        }

        String email = null;
        RegisterSecondaryArgument mode = config.registrationSecondArgument();
        if (mode == RegisterSecondaryArgument.CONFIRMATION
            && (second == null || !Objects.equals(first, second))) {
            return AccountResult.PASSWORD_MISMATCH;
        }
        if (mode == RegisterSecondaryArgument.EMAIL_MANDATORY) {
            if (second == null || !validEmail(second.trim())) return AccountResult.EMAIL_INVALID;
            email = second.trim();
        } else if (mode == RegisterSecondaryArgument.EMAIL_OPTIONAL && second != null) {
            if (!validEmail(second.trim())) return AccountResult.EMAIL_INVALID;
            email = second.trim();
        } else if (mode == RegisterSecondaryArgument.NONE && second != null) {
            return AccountResult.INVALID_INPUT;
        }
        return registerPasswordAccount(name, rawName.trim(), first, email, ip, true, bypassIpLimit);
    }

    /**
     * Connection-bound registration entry point. A delayed task from a player that has already
     * disconnected must not create or overwrite state for a rapid reconnect with the same name.
     */
    public AccountResult registerIfConnection(String rawName, String first, String second, String ip,
                                              long connectionToken) {
        return registerIfConnection(rawName, first, second, ip, connectionToken, false);
    }

    /** Connection-bound registration with an explicit per-IP limit bypass. */
    public AccountResult registerIfConnection(String rawName, String first, String second, String ip,
                                              long connectionToken, boolean bypassIpLimit) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return register(rawName, first, second, ip, bypassIpLimit);
        }
    }

    private AccountResult registerPasswordAccount(String name, String realName, String password,
                                                  String email, String ip, boolean enforceLimits,
                                                  boolean bypassIpLimit) {
        if (!validPassword(password) || (email != null && !validEmail(email))) {
            return AccountResult.INVALID_INPUT;
        }
        if (config.unsafePasswords().contains(password.toLowerCase(Locale.ROOT))) {
            return AccountResult.UNSAFE_PASSWORD;
        }
        if (enforceLimits && config.captchaEnabled() && config.captchaForRegistration()
            && !consumeCaptchaPass(failureKey(name, ip))) {
            return AccountResult.CAPTCHA_REQUIRED;
        }
        synchronized (lockFor(name)) {
            DataSource source = dataSource;
            DataSource.CheckResult available = source.checkAuthAvailable(name);
            if (!available.successful()) return AccountResult.DATABASE_ERROR;
            if (available.available()) return AccountResult.ALREADY_REGISTERED;
            if (enforceLimits) {
                DataSource.CountResult byIp = source.countRegisteredByIp(normalizeIp(ip));
                if (!byIp.successful()) return AccountResult.DATABASE_ERROR;
                if (!bypassIpLimit && config.maxRegistrationsPerIp() > 0
                    && byIp.count() >= config.maxRegistrationsPerIp()) {
                    return AccountResult.REGISTRATION_LIMIT;
                }
            }
            if (email != null && enforceLimits) {
                DataSource.CountResult byEmail = source.countRegisteredByEmail(email);
                if (!byEmail.successful()) return AccountResult.DATABASE_ERROR;
                if (config.maxRegistrationsPerEmail() > 0
                    && byEmail.count() >= config.maxRegistrationsPerEmail()) {
                    return AccountResult.EMAIL_LIMIT;
                }
            }
            HashedPassword hashed;
            try {
                hashed = passwordSecurity.computeHash(password, name);
            } catch (RuntimeException exception) {
                return AccountResult.CONFIG_ERROR;
            }
            PlayerAuth auth = PlayerAuth.builder()
                .name(name)
                .realName(realName)
                .password(hashed.getHash(), hashed.getSalt())
                .lastIp(normalizeIp(ip))
                .registrationIp(normalizeIp(ip))
                .registrationDate(System.currentTimeMillis())
                .email(email)
                .locWorld("world")
                .build();
            return source.saveAuth(auth) ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
        }
    }

    private AccountResult registerEmailAccount(String name, String realName, String email, String ip,
                                               boolean bypassIpLimit) {
        if (!config.emailRegistrationConfigured()) return AccountResult.EMAIL_NOT_CONFIGURED;
        if (config.captchaEnabled() && config.captchaForRegistration()
            && !consumeCaptchaPass(failureKey(name, ip))) {
            return AccountResult.CAPTCHA_REQUIRED;
        }
        int length = Math.max(config.minPasswordLength(), Math.min(config.maxPasswordLength(),
            config.emailGeneratedPasswordLength()));
        String generatedPassword = RandomStringUtils.generate(length);
        AccountResult result;
        synchronized (lockFor(name)) {
            DataSource source = dataSource;
            DataSource.CheckResult available = source.checkAuthAvailable(name);
            if (!available.successful()) return AccountResult.DATABASE_ERROR;
            if (available.available()) return AccountResult.ALREADY_REGISTERED;
            DataSource.CountResult byIp = source.countRegisteredByIp(normalizeIp(ip));
            DataSource.CountResult byEmail = source.countRegisteredByEmail(email);
            if (!byIp.successful() || !byEmail.successful()) return AccountResult.DATABASE_ERROR;
            if (!bypassIpLimit && config.maxRegistrationsPerIp() > 0
                && byIp.count() >= config.maxRegistrationsPerIp()) {
                return AccountResult.REGISTRATION_LIMIT;
            }
            if (config.maxRegistrationsPerEmail() > 0 && byEmail.count() >= config.maxRegistrationsPerEmail()) {
                return AccountResult.EMAIL_LIMIT;
            }
            if (!EmailSender.send(config, email, "AuthMe registration",
                "Your AuthMe password is: " + generatedPassword)) {
                return AccountResult.EMAIL_SEND_FAILED;
            }
            try {
                HashedPassword hashed = passwordSecurity.computeHash(generatedPassword, name);
                PlayerAuth auth = PlayerAuth.builder()
                    .name(name).realName(realName).password(hashed.getHash(), hashed.getSalt())
                    .lastIp(normalizeIp(ip)).registrationIp(normalizeIp(ip))
                    .registrationDate(System.currentTimeMillis()).email(email).locWorld("world").build();
                result = source.saveAuth(auth) ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
            } catch (RuntimeException exception) {
                result = AccountResult.CONFIG_ERROR;
            }
        }
        return result;
    }

    public AccountResult login(String rawName, String password, String ip, boolean session) {
        String name = normalizeName(rawName);
        if (name == null || !validPassword(password)) return AccountResult.INVALID_INPUT;
        String failureKey = name + "|" + normalizeIp(ip);
        synchronized (lockFor(name)) {
            if (isCaptchaRequired(failureKey)) return AccountResult.CAPTCHA_REQUIRED;
            if (isRateLimited(failureKey)) return AccountResult.RATE_LIMITED;
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            PlayerAuth auth = lookup.auth();
            if (auth == null) return AccountResult.NOT_REGISTERED;
            if (!caseMatches(auth, rawName)) return AccountResult.NOT_REGISTERED;
            PasswordSecurity.VerificationResult verification = passwordSecurity.verify(
                password, auth.toHashedPassword(), name);
            if (verification == null) {
                if (!recordFailure(failureKey)) return AccountResult.DATABASE_ERROR;
                if (isCaptchaRequired(failureKey)) return AccountResult.CAPTCHA_REQUIRED;
                return isBanned(failureKey) ? AccountResult.RATE_LIMITED : AccountResult.WRONG_PASSWORD;
            }
            clearFailure(failureKey);
            if (verification.isLegacy()) {
                try {
                    if (!dataSource.updatePasswordIfMatches(name, auth.toHashedPassword(),
                        passwordSecurity.computeHash(password, name))) {
                        // The row may have changed on another AuthMe instance. Treat a failed
                        // compare-and-set as a database failure rather than overwriting the newer
                        // password with this login's delayed legacy migration.
                        return AccountResult.DATABASE_ERROR;
                    }
                } catch (RuntimeException exception) {
                    return AccountResult.CONFIG_ERROR;
                }
            }
            if (auth.getTotpKey() != null && !auth.getTotpKey().isBlank()) {
                return TotpProvider.isPlausibleSecret(auth.getTotpKey())
                    ? AccountResult.TOTP_REQUIRED : AccountResult.CONFIG_ERROR;
            }
            return acquireLogin(name, normalizeIp(ip), session);
        }
    }

    /** Performs password login only while the supplied connection generation remains current. */
    public AccountResult loginIfConnection(String rawName, String password, String ip, boolean session,
                                           long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return login(rawName, password, ip, session);
        }
    }

    public AccountResult verifyCaptchaIfConnection(String rawName, String ip, String code,
                                                    long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return verifyCaptcha(rawName, ip, code);
        }
    }

    /** Attempts AuthMe's IP-bound session login without accepting a password-less stale flag. */
    public AccountResult sessionLogin(String rawName, String ip) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        String currentIp = normalizeIp(ip);
        // A missing address is not an identity binding. Treating the sentinel as a
        // real address would let every connection with an unavailable socket resume
        // an account's persisted session.
        if ("unknown".equals(currentIp)) return AccountResult.SESSION_INVALID;
        synchronized (lockFor(name)) {
            if (!config.sessionEnabled()) return AccountResult.SESSION_INVALID;
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            PlayerAuth auth = lookup.auth();
            if (auth != null && !caseMatches(auth, rawName)) return AccountResult.SESSION_INVALID;
            long now = System.currentTimeMillis();
            long lastLogin = auth == null || auth.getLastLogin() == null ? 0L : auth.getLastLogin();
            boolean valid = auth != null && auth.hasSession()
                && !"unknown".equals(normalizeIp(auth.getLastIp()))
                && Objects.equals(currentIp, normalizeIp(auth.getLastIp()))
                && lastLogin > 0L && now >= lastLogin
                && now - lastLogin <= config.sessionTimeoutMinutes() * 60_000L;
            if (!valid) return AccountResult.SESSION_INVALID;
            if (auth.getTotpKey() != null && !auth.getTotpKey().isBlank()) {
                // A persisted Session is still a password bypass. It must not bypass
                // the account's configured second factor.
                return TotpProvider.isPlausibleSecret(auth.getTotpKey())
                    ? AccountResult.TOTP_REQUIRED : AccountResult.CONFIG_ERROR;
            }
            return acquireLogin(name, currentIp, true);
        }
    }

    /** Session login guarded by the connection generation that requested it. */
    public AccountResult sessionLoginIfConnection(String rawName, String ip, long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return sessionLogin(rawName, ip);
        }
    }

    /** Performs the safe online-mode Premium bypass only when the stored UUID matches exactly. */
    public AccountResult premiumLogin(String rawName, java.util.UUID playerUuid,
                                      boolean onlineMode, String ip) {
        String name = normalizeName(rawName);
        if (name == null || playerUuid == null || !onlineMode || !config.enablePremium()) {
            return AccountResult.PREMIUM_UNAVAILABLE;
        }
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            PlayerAuth auth = lookup.auth();
            if (auth == null || !caseMatches(auth, rawName) || !playerUuid.equals(auth.getPremiumUuid())) {
                return AccountResult.PREMIUM_MISMATCH;
            }
            if (auth.getTotpKey() != null && !auth.getTotpKey().isBlank()) {
                // A Premium UUID proves the online identity, not the account's second factor.
                return AccountResult.TOTP_REQUIRED;
            }
            String currentIp = normalizeIp(ip);
            return acquireLogin(name, currentIp, config.sessionEnabled());
        }
    }

    /** Premium login guarded by the connection generation that requested it. */
    public AccountResult premiumLoginIfConnection(String rawName, java.util.UUID playerUuid,
                                                   boolean onlineMode, String ip,
                                                   long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return premiumLogin(rawName, playerUuid, onlineMode, ip);
        }
    }

    public AccountResult enablePremium(String rawName, java.util.UUID playerUuid, boolean onlineMode) {
        String name = normalizeName(rawName);
        if (name == null || playerUuid == null || !onlineMode || !config.enablePremium()) {
            return AccountResult.PREMIUM_UNAVAILABLE;
        }
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            if (lookup.auth() == null) return AccountResult.NOT_REGISTERED;
            return dataSource.updatePremiumUuid(name, playerUuid)
                ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
        }
    }

    public AccountResult disablePremium(String rawName) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            if (lookup.auth() == null) return AccountResult.NOT_REGISTERED;
            return dataSource.updatePremiumUuid(name, null)
                ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
        }
    }

    /** Returns a bounded, short-lived challenge for a player whose password attempts need CAPTCHA. */
    public String captchaChallenge(String rawName, String ip) {
        String name = normalizeName(rawName);
        if (name == null || !config.captchaEnabled()) return "";
        String key = failureKey(name, ip);
        CaptchaState state = captchas.get(key);
        long now = System.currentTimeMillis();
        if (state == null || state.expiresAt <= now) {
            if (captchas.size() >= MAX_CAPTCHAS && !captchas.containsKey(key)) {
                captchas.keySet().stream().findFirst().ifPresent(captchas::remove);
            }
            state = new CaptchaState(RandomStringUtils.generateLowerUpper(config.captchaLength()),
                now + Math.max(1L, config.captchaResetMinutes()) * 60_000L);
            captchas.put(key, state);
        }
        return state.code;
    }

    public AccountResult verifyCaptcha(String rawName, String ip, String code) {
        String name = normalizeName(rawName);
        if (name == null || code == null || code.length() > 64) return AccountResult.INVALID_INPUT;
        String key = failureKey(name, ip);
        CaptchaState state = captchas.get(key);
        if (state == null || state.expiresAt <= System.currentTimeMillis()) {
            captchas.remove(key, state);
            return AccountResult.CAPTCHA_INVALID;
        }
        if (!java.security.MessageDigest.isEqual(state.code.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
            code.trim().getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
            return AccountResult.CAPTCHA_INVALID;
        }
        captchas.remove(key, state);
        clearFailure(key);
        long now = System.currentTimeMillis();
        if (captchaPasses.size() >= MAX_CAPTCHAS && !captchaPasses.containsKey(key)) {
            captchaPasses.keySet().stream().findFirst().ifPresent(captchaPasses::remove);
        }
        captchaPasses.put(key, now + Math.max(60_000L, config.captchaResetMinutes() * 60_000L));
        return AccountResult.SUCCESS;
    }

    private boolean consumeCaptchaPass(String key) {
        Long expiresAt = captchaPasses.get(key);
        long now = System.currentTimeMillis();
        if (expiresAt == null) return false;
        if (expiresAt <= now || !captchaPasses.remove(key, expiresAt)) return false;
        return true;
    }

    /** Completes the second factor after a password login returned {@link AccountResult#TOTP_REQUIRED}. */
    public AccountResult verifyTotp(String rawName, String code, String ip, boolean session) {
        String name = normalizeName(rawName);
        if (name == null || code == null || code.length() > 32) return AccountResult.INVALID_INPUT;
        String failureKey = name + "|totp|" + normalizeIp(ip);
        synchronized (lockFor(name)) {
            if (isRateLimited(failureKey)) return AccountResult.RATE_LIMITED;
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            PlayerAuth auth = lookup.auth();
            if (auth == null) return AccountResult.NOT_REGISTERED;
            if (!TotpProvider.isPlausibleSecret(auth.getTotpKey())) return AccountResult.TOTP_NOT_ENABLED;
            if (!TotpProvider.validateCode(auth.getTotpKey(), code)) {
                if (!recordFailure(failureKey)) return AccountResult.DATABASE_ERROR;
                return isBanned(failureKey) ? AccountResult.RATE_LIMITED : AccountResult.WRONG_TOTP;
            }
            clearFailure(failureKey);
            return acquireLogin(name, normalizeIp(ip), session);
        }
    }

    public AccountResult verifyTotpIfConnection(String rawName, String code, String ip, boolean session,
                                                long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return verifyTotp(rawName, code, ip, session);
        }
    }

    public TotpResult enableTotp(String rawName) {
        String name = normalizeName(rawName);
        if (name == null) return new TotpResult(AccountResult.INVALID_INPUT, "");
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return new TotpResult(AccountResult.DATABASE_ERROR, "");
            if (lookup.auth() == null) return new TotpResult(AccountResult.NOT_REGISTERED, "");
            if (TotpProvider.isPlausibleSecret(lookup.auth().getTotpKey())) {
                return new TotpResult(AccountResult.TOTP_ALREADY_ENABLED, "");
            }
            String secret = TotpProvider.generateSecret();
            // Keep the generated secret out of the account row until the player
            // proves possession with a current TOTP code.
            return new TotpResult(AccountResult.SUCCESS, secret);
        }
    }

    public TotpResult enableTotpIfConnection(String rawName, long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return new TotpResult(AccountResult.INVALID_INPUT, "");
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) {
                return new TotpResult(AccountResult.STALE_CONNECTION, "");
            }
            return enableTotp(rawName);
        }
    }

    /** Persists a TOTP setup secret only after its first code has been verified. */
    public AccountResult confirmTotp(String rawName, String secret, String code) {
        String name = normalizeName(rawName);
        if (name == null || secret == null || code == null || code.length() > 32
            || !TotpProvider.isPlausibleSecret(secret)) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            if (lookup.auth() == null) return AccountResult.NOT_REGISTERED;
            if (TotpProvider.isPlausibleSecret(lookup.auth().getTotpKey())) {
                return AccountResult.TOTP_ALREADY_ENABLED;
            }
            if (!TotpProvider.validateCode(secret, code)) return AccountResult.WRONG_TOTP;
            return dataSource.updateTotpKey(name, secret)
                ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
        }
    }

    public AccountResult confirmTotpIfConnection(String rawName, String secret, String code,
                                                 long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return confirmTotp(rawName, secret, code);
        }
    }

    public AccountResult disableTotp(String rawName, String code) {
        String name = normalizeName(rawName);
        if (name == null || code == null || code.length() > 32) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            if (lookup.auth() == null) return AccountResult.NOT_REGISTERED;
            if (!TotpProvider.isPlausibleSecret(lookup.auth().getTotpKey())) return AccountResult.TOTP_NOT_ENABLED;
            if (!TotpProvider.validateCode(lookup.auth().getTotpKey(), code)) return AccountResult.WRONG_TOTP;
            return dataSource.updateTotpKey(name, null) ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
        }
    }

    public AccountResult disableTotpIfConnection(String rawName, String code, long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return disableTotp(rawName, code);
        }
    }

    public AccountResult addEmail(String rawName, String email, String confirmation) {
        String name = normalizeName(rawName);
        String value = email == null ? "" : email.trim();
        if (name == null || !validEmail(value)) return AccountResult.EMAIL_INVALID;
        if (!Objects.equals(value.toLowerCase(Locale.ROOT),
            confirmation == null ? null : confirmation.trim().toLowerCase(Locale.ROOT))) {
            return AccountResult.EMAIL_MISMATCH;
        }
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            if (lookup.auth() == null) return AccountResult.NOT_REGISTERED;
            DataSource.CountResult count = dataSource.countRegisteredByEmail(value);
            if (!count.successful()) return AccountResult.DATABASE_ERROR;
            if (config.maxRegistrationsPerEmail() > 0 && count.count() >= config.maxRegistrationsPerEmail()) {
                return AccountResult.EMAIL_LIMIT;
            }
            if (config.emailRequireVerification()) {
                return sendEmailVerification(name, value, false);
            }
            return dataSource.updateEmail(name, value) ? AccountResult.EMAIL_ADDED : AccountResult.DATABASE_ERROR;
        }
    }

    public AccountResult addEmailIfConnection(String rawName, String email, String confirmation,
                                               long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return addEmail(rawName, email, confirmation);
        }
    }

    public AccountResult changeEmail(String rawName, String oldEmail, String newEmail) {
        String name = normalizeName(rawName);
        String oldValue = oldEmail == null ? "" : oldEmail.trim();
        String newValue = newEmail == null ? "" : newEmail.trim();
        if (name == null || !validEmail(oldValue) || !validEmail(newValue)) return AccountResult.EMAIL_INVALID;
        if (oldValue.equalsIgnoreCase(newValue)) return AccountResult.EMAIL_MISMATCH;
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            if (lookup.auth() == null || lookup.auth().getEmail() == null
                || !oldValue.equalsIgnoreCase(lookup.auth().getEmail())) return AccountResult.EMAIL_INVALID;
            DataSource.CountResult count = dataSource.countRegisteredByEmail(newValue);
            if (!count.successful()) return AccountResult.DATABASE_ERROR;
            if (config.maxRegistrationsPerEmail() > 0 && count.count() >= config.maxRegistrationsPerEmail()) {
                return AccountResult.EMAIL_LIMIT;
            }
            if (config.emailRequireVerification()) return sendEmailVerification(name, newValue, false);
            return dataSource.updateEmail(name, newValue) ? AccountResult.EMAIL_CHANGED : AccountResult.DATABASE_ERROR;
        }
    }

    public AccountResult changeEmailIfConnection(String rawName, String oldEmail, String newEmail,
                                                  long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return changeEmail(rawName, oldEmail, newEmail);
        }
    }

    /** Sends recovery mail without disclosing whether the supplied address exists. */
    public AccountResult requestEmailRecovery(String rawName, String email, String ip) {
        String name = normalizeName(rawName);
        String value = email == null ? "" : email.trim();
        if (name == null || !validEmail(value) || !config.emailEnabled()) {
            return AccountResult.EMAIL_RECOVERY_SENT;
        }
        String throttleKey = name + "|" + normalizeIp(ip);
        long now = System.currentTimeMillis();
        long cooldown = Math.max(1L, config.emailRecoveryCooldownSeconds()) * 1000L;
        synchronized (recoveryLastSent) {
            recoveryLastSent.entrySet().removeIf(entry -> now - entry.getValue() >= cooldown);
            Long previous = recoveryLastSent.get(throttleKey);
            if (previous != null && now - previous < cooldown) return AccountResult.EMAIL_RECOVERY_SENT;
            if (recoveryLastSent.size() >= MAX_EMAIL_CHALLENGES && !recoveryLastSent.containsKey(throttleKey)) {
                recoveryLastSent.keySet().stream().findFirst().ifPresent(recoveryLastSent::remove);
            }
            recoveryLastSent.put(throttleKey, now);
        }
        synchronized (lockFor(name)) {
            DataSource authSource = dataSource;
            PlayerAuth account = authSource.getAuthByEmail(value);
            if (account == null || account.getName() == null
                || !name.equalsIgnoreCase(account.getName()) || account.getEmail() == null
                || !value.equalsIgnoreCase(account.getEmail())) return AccountResult.EMAIL_RECOVERY_SENT;
            String code = RandomStringUtils.generateNum(config.emailRecoveryCodeLength());
            putEmailChallenge("recover:" + name,
                new EmailChallenge(account.getEmail(), code,
                    now + Math.max(60L, config.emailRecoveryTimeoutSeconds()) * 1000L, true));
            boolean sent = EmailSender.send(config, account.getEmail(), "AuthMe password recovery",
                "Your AuthMe recovery code is: " + code);
            if (!sent) emailChallenges.remove("recover:" + name);
            return AccountResult.EMAIL_RECOVERY_SENT;
        }
    }

    public AccountResult requestEmailRecoveryIfConnection(String rawName, String email, String ip,
                                                           long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return requestEmailRecovery(rawName, email, ip);
        }
    }

    public AccountResult confirmEmail(String rawName, String code) {
        String name = normalizeName(rawName);
        if (name == null || code == null || code.length() > 64) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            EmailChallenge challenge = emailChallenges.get("verify:" + name);
            boolean recovery = false;
            if (challenge == null) {
                challenge = emailChallenges.get("recover:" + name);
                recovery = true;
            }
            if (challenge == null || challenge.expiresAt <= System.currentTimeMillis()) {
                if (recovery) emailChallenges.remove("recover:" + name);
                else emailChallenges.remove("verify:" + name);
                return AccountResult.EMAIL_CODE_INVALID;
            }
            if (!java.security.MessageDigest.isEqual(challenge.code.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                code.trim().getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
                if (++challenge.failedAttempts >= config.emailRecoveryMaxAttempts()) {
                    emailChallenges.remove((recovery ? "recover:" : "verify:") + name, challenge);
                }
                return AccountResult.EMAIL_CODE_INVALID;
            }
            challenge.verified = true;
            challenge.verifiedAt = System.currentTimeMillis();
            if (recovery) return AccountResult.EMAIL_CONFIRMED;
            boolean updated = dataSource.updateEmail(name, challenge.email);
            if (updated) emailChallenges.remove("verify:" + name, challenge);
            return updated ? AccountResult.EMAIL_CONFIRMED : AccountResult.DATABASE_ERROR;
        }
    }

    public AccountResult confirmEmailIfConnection(String rawName, String code, long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return confirmEmail(rawName, code);
        }
    }

    public AccountResult setRecoveredPassword(String rawName, String password) {
        String name = normalizeName(rawName);
        if (name == null || !validPassword(password)) return AccountResult.INVALID_INPUT;
        if (config.unsafePasswords().contains(password.toLowerCase(Locale.ROOT))) {
            return AccountResult.UNSAFE_PASSWORD;
        }
        synchronized (lockFor(name)) {
            EmailChallenge challenge = emailChallenges.get("recover:" + name);
            long now = System.currentTimeMillis();
            if (challenge == null || !challenge.recovery || !challenge.verified
                || now - challenge.verifiedAt > Math.max(60L, config.emailPasswordChangeTimeoutSeconds()) * 1000L) {
                return AccountResult.EMAIL_CODE_INVALID;
            }
            try {
                boolean updated = dataSource.updatePasswordAndClearLogin(
                    name, passwordSecurity.computeHash(password, name));
                if (updated) {
                    emailChallenges.remove("recover:" + name, challenge);
                }
                return updated ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
            } catch (RuntimeException exception) {
                return AccountResult.CONFIG_ERROR;
            }
        }
    }

    public AccountResult setRecoveredPasswordIfConnection(String rawName, String password,
                                                           long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return setRecoveredPassword(rawName, password);
        }
    }

    public String email(String rawName) {
        String name = normalizeName(rawName);
        if (name == null) return "";
        DataSource.LookupResult lookup = dataSource.lookupAuth(name);
        return lookup.successful() && lookup.auth() != null && lookup.auth().getEmail() != null
            ? lookup.auth().getEmail() : "";
    }

    public AccountResult logout(String rawName) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            DataSource.CheckResult available = dataSource.checkAuthAvailable(name);
            if (!available.successful()) return AccountResult.DATABASE_ERROR;
            if (!available.available()) return AccountResult.NOT_REGISTERED;
            Long ownedVersion = loginLeases.get(name);
            if (ownedVersion == null || ownedVersion <= 0L) return AccountResult.SUCCESS;
            boolean cleared = dataSource.clearLoginIfLastLogin(name, ownedVersion);
            if (cleared) loginLeases.remove(name, ownedVersion);
            return cleared ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
        }
    }

    public AccountResult unregister(String rawName, String password) {
        String name = normalizeName(rawName);
        if (name == null || !validPassword(password)) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            if (lookup.auth() == null) return AccountResult.NOT_REGISTERED;
            if (passwordSecurity.verify(password, lookup.auth().toHashedPassword(), name) == null) {
                return AccountResult.WRONG_PASSWORD;
            }
            return dataSource.removeAuth(name) ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
        }
    }

    public AccountResult unregisterIfConnection(String rawName, String password, long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return unregister(rawName, password);
        }
    }

    public AccountResult changePassword(String rawName, String oldPassword, String newPassword) {
        String name = normalizeName(rawName);
        if (name == null || !validPassword(oldPassword) || !validPassword(newPassword)) {
            return AccountResult.INVALID_INPUT;
        }
        if (config.unsafePasswords().contains(newPassword.toLowerCase(Locale.ROOT))) {
            return AccountResult.UNSAFE_PASSWORD;
        }
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            if (lookup.auth() == null) return AccountResult.NOT_REGISTERED;
            if (passwordSecurity.verify(oldPassword, lookup.auth().toHashedPassword(), name) == null) {
                return AccountResult.WRONG_PASSWORD;
            }
            try {
                return dataSource.updatePassword(name, passwordSecurity.computeHash(newPassword, name))
                    ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
            } catch (RuntimeException exception) {
                return AccountResult.CONFIG_ERROR;
            }
        }
    }

    public AccountResult changePasswordIfConnection(String rawName, String oldPassword, String newPassword,
                                                     long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return changePassword(rawName, oldPassword, newPassword);
        }
    }

    public AccountResult enablePremiumIfConnection(String rawName, java.util.UUID playerUuid,
                                                    boolean onlineMode, long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return enablePremium(rawName, playerUuid, onlineMode);
        }
    }

    public AccountResult disablePremiumIfConnection(String rawName, long connectionToken) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            if (!isCurrentConnectionLocked(name, connectionToken)) return AccountResult.STALE_CONNECTION;
            return disablePremium(rawName);
        }
    }

    public AccountResult adminRegister(String rawName, String password) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        return registerPasswordAccount(name, rawName.trim(), password, null, "admin", false, false);
    }

    public AccountResult adminUnregister(String rawName) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            DataSource.CheckResult available = dataSource.checkAuthAvailable(name);
            if (!available.successful()) return AccountResult.DATABASE_ERROR;
            if (!available.available()) return AccountResult.NOT_REGISTERED;
            return dataSource.removeAuth(name) ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
        }
    }

    public AccountResult adminSetPassword(String rawName, String password) {
        String name = normalizeName(rawName);
        if (name == null || !validPassword(password)) return AccountResult.INVALID_INPUT;
        if (config.unsafePasswords().contains(password.toLowerCase(Locale.ROOT))) {
            return AccountResult.UNSAFE_PASSWORD;
        }
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            if (lookup.auth() == null) return AccountResult.NOT_REGISTERED;
            try {
                return dataSource.updatePassword(name, passwordSecurity.computeHash(password, name))
                    ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
            } catch (RuntimeException exception) {
                return AccountResult.CONFIG_ERROR;
            }
        }
    }

    public AccountResult adminAuth(String rawName) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            PlayerAuth auth = lookup.auth();
            if (auth == null) return AccountResult.NOT_REGISTERED;
            return acquireLogin(name, normalizeIp(auth.getLastIp()), config.sessionEnabled());
        }
    }

    public AccountResult adminUnauth(String rawName) {
        return logout(rawName);
    }

    public AccountResult adminSetEmail(String rawName, String email) {
        String name = normalizeName(rawName);
        String value = email == null ? "" : email.trim();
        if (name == null || !validEmail(value)) return AccountResult.EMAIL_INVALID;
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            if (lookup.auth() == null) return AccountResult.NOT_REGISTERED;
            return dataSource.updateEmail(name, value) ? AccountResult.EMAIL_CHANGED : AccountResult.DATABASE_ERROR;
        }
    }

    public AccountResult adminDisableTotp(String rawName) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            if (lookup.auth() == null) return AccountResult.NOT_REGISTERED;
            if (!TotpProvider.isPlausibleSecret(lookup.auth().getTotpKey())) return AccountResult.TOTP_NOT_ENABLED;
            return dataSource.updateTotpKey(name, null) ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
        }
    }

    public AccountResult adminSetPremium(String rawName, java.util.UUID premiumUuid) {
        String name = normalizeName(rawName);
        if (name == null || !config.enablePremium()) return AccountResult.PREMIUM_UNAVAILABLE;
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            if (lookup.auth() == null) return AccountResult.NOT_REGISTERED;
            return dataSource.updatePremiumUuid(name, premiumUuid)
                ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
        }
    }

    public DataSource.QueryResult<java.util.List<String>> accountsByIp(String ip) {
        return dataSource.queryRegisteredNamesByIp(normalizeIp(ip));
    }

    public DataSource.QueryResult<java.util.List<PlayerAuth>> recentAccounts(int limit) {
        return dataSource.queryRecentAccounts(Math.min(100, Math.max(1, limit)));
    }

    public DataSource.OperationResult purge(long cutoffMillis, int limit) {
        return dataSource.purgeRegisteredBefore(cutoffMillis, Math.min(10_000, Math.max(1, limit)));
    }

    /** Reads the bounded purge set before deletion so platform adapters can clean optional files. */
    public DataSource.QueryResult<java.util.List<PlayerAuth>> purgeCandidates(long cutoffMillis, int limit) {
        return dataSource.queryPurgeCandidates(cutoffMillis, Math.min(10_000, Math.max(1, limit)));
    }

    /** Revalidates an old-account candidate in the database immediately before deleting it. */
    public DataSource.OperationResult purgeIfUnchanged(PlayerAuth expected, long cutoffMillis) {
        if (expected == null || expected.getName() == null) {
            return new DataSource.OperationResult(0, false);
        }
        String name = normalizeName(expected.getName());
        if (name == null) return new DataSource.OperationResult(0, false);
        synchronized (lockFor(name)) {
            DataSource.OperationResult result = dataSource.removeAuthIfUnchanged(expected, cutoffMillis);
            if (result.successful() && result.affected() > 0) {
                loginLeases.remove(name);
                connectionEpochs.remove(name);
            }
            return result;
        }
    }

    /** Resets one account's persisted quit location to the AuthMe default world/origin. */
    public AccountResult resetPosition(String rawName) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            if (lookup.auth() == null) return AccountResult.NOT_REGISTERED;
            return dataSource.updateLocation(name, 0.0, 64.0, 0.0, 0.0f, 0.0f,
                "minecraft:overworld") ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
        }
    }

    /** Resets all persisted quit locations; the backend bounds the single bulk operation. */
    public DataSource.OperationResult resetAllPositions() {
        return dataSource.resetAllLocations()
            ? new DataSource.OperationResult(0, true)
            : new DataSource.OperationResult(0, false);
    }

    /** Deletes one account only when an explicit force flag has been supplied. */
    public AccountResult purgePlayer(String rawName, boolean force) {
        String name = normalizeName(rawName);
        if (name == null) return AccountResult.INVALID_INPUT;
        synchronized (lockFor(name)) {
            DataSource.LookupResult lookup = dataSource.lookupAuth(name);
            if (!lookup.successful()) return AccountResult.DATABASE_ERROR;
            if (lookup.auth() == null) return AccountResult.NOT_REGISTERED;
            if (!force) return AccountResult.PURGE_CONFIRMATION_REQUIRED;
            return dataSource.removeAuth(name) ? AccountResult.SUCCESS : AccountResult.DATABASE_ERROR;
        }
    }

    public boolean backup(java.nio.file.Path destination) {
        return dataSource.backup(destination);
    }

    public DataSource.LookupResult lookup(String rawName) {
        String name = normalizeName(rawName);
        if (name == null) return new DataSource.LookupResult(null, true);
        return dataSource.lookupAuth(name);
    }

    @Override
    public synchronized void close() {
        DataSource source = dataSource;
        dataSource = null;
        captchas.clear();
        captchaPasses.clear();
        emailChallenges.clear();
        recoveryLastSent.clear();
        connectionEpochs.clear();
        loginLeases.clear();
        if (source != null) source.close();
    }

    /** Checks whether this runtime still owns the database login fence for an account. */
    public LoginLeaseStatus loginLeaseStatus(String rawName) {
        String name = normalizeName(rawName);
        if (name == null) return LoginLeaseStatus.REVOKED;
        Long owned = loginLeases.get(name);
        if (owned == null || owned <= 0L) return LoginLeaseStatus.REVOKED;
        DataSource.LoginLeaseResult lease = dataSource.renewLoginLease(
            name, owned, System.currentTimeMillis());
        if (!lease.successful()) return LoginLeaseStatus.ERROR;
        return lease.active() ? LoginLeaseStatus.OWNED : LoginLeaseStatus.REVOKED;
    }

    public enum LoginLeaseStatus { OWNED, REVOKED, ERROR }

    private boolean isCurrentConnectionLocked(String name, long token) {
        return connectionEpochs.getOrDefault(name, 0L) == token;
    }

    private Object lockFor(String name) {
        return accountLockStripes[Math.floorMod(name.hashCode(), accountLockStripes.length)];
    }

    private static Object[] createLockStripes() {
        Object[] locks = new Object[LOCK_STRIPES];
        for (int i = 0; i < locks.length; i++) locks[i] = new Object();
        return locks;
    }

    private boolean isRateLimited(String key) {
        long now = System.currentTimeMillis();
        long resetMillis = Math.max(60_000L, config.tempbanCounterResetMinutes() * 60_000L);
        DataSource.FailureStateResult account = dataSource.readFailureState(
            sharedFailureKey(key), now, resetMillis);
        DataSource.FailureStateResult source = dataSource.readFailureState(
            sourceFailureKey(key), now, resetMillis);
        if (!account.successful() || !source.successful()) return true;
        return account.bannedUntil() > now || source.bannedUntil() > now
            || now - account.lastFailure() < MIN_RETRY_DELAY_MILLIS;
    }

    private boolean isCaptchaRequired(String key) {
        if (!config.captchaEnabled()) return false;
        CaptchaState challenge = captchas.get(key);
        if (challenge != null && challenge.expiresAt > System.currentTimeMillis()) return true;
        DataSource.FailureStateResult state = dataSource.readFailureState(sharedFailureKey(key),
            System.currentTimeMillis(), Math.max(60_000L, config.captchaResetMinutes() * 60_000L));
        if (!state.successful()) return true;
        if (state.windowStarted() <= 0L || state.windowStarted() + Math.max(60_000L,
            config.captchaResetMinutes() * 60_000L) <= System.currentTimeMillis()) return false;
        if (state.attempts() < Math.max(1, config.maxLoginTriesForCaptcha())) return false;
        captchaChallenge(key.substring(0, key.indexOf('|')), key.substring(key.indexOf('|') + 1));
        return true;
    }

    private String failureKey(String name, String ip) { return name + "|" + normalizeIp(ip); }

    private AccountResult sendEmailVerification(String name, String email, boolean recovery) {
        if (!config.emailEnabled()) return AccountResult.EMAIL_NOT_CONFIGURED;
        String code = RandomStringUtils.generateNum(config.emailRecoveryCodeLength());
        String key = (recovery ? "recover:" : "verify:") + name;
        EmailChallenge challenge = new EmailChallenge(email, code,
            System.currentTimeMillis() + Math.max(60L, config.emailVerificationTimeoutSeconds()) * 1000L,
            recovery);
        putEmailChallenge(key, challenge);
        boolean sent = EmailSender.send(config, email, "AuthMe e-mail verification",
            "Your AuthMe verification code is: " + code);
        if (!sent) {
            emailChallenges.remove(key, challenge);
            return AccountResult.EMAIL_SEND_FAILED;
        }
        return AccountResult.EMAIL_VERIFICATION_SENT;
    }

    private void putEmailChallenge(String key, EmailChallenge challenge) {
        if (emailChallenges.size() >= MAX_EMAIL_CHALLENGES && !emailChallenges.containsKey(key)) {
            emailChallenges.keySet().stream().findFirst().ifPresent(emailChallenges::remove);
        }
        emailChallenges.put(key, challenge);
    }

    private boolean recordFailure(String key) {
        long now = System.currentTimeMillis();
        long resetMillis = Math.max(60_000L, config.tempbanCounterResetMinutes() * 60_000L);
        DataSource.FailureStateResult account = dataSource.recordFailureState(
            sharedFailureKey(key), now, resetMillis,
            config.tempbanEnabled() ? Math.max(1, config.tempbanMaxLoginTries()) : 0,
            Math.max(60_000L, config.tempbanLengthMinutes() * 60_000L));
        DataSource.FailureStateResult source = dataSource.recordFailureState(
            sourceFailureKey(key), now, resetMillis,
            config.tempbanEnabled() ? Math.max(1, config.tempbanMaxLoginTries()) : 0,
            Math.max(60_000L, config.tempbanLengthMinutes() * 60_000L));
        return account.successful() && source.successful();
    }

    private boolean isBanned(String key) {
        long now = System.currentTimeMillis();
        DataSource.FailureStateResult account = dataSource.readFailureState(sharedFailureKey(key), now,
            Math.max(60_000L, config.tempbanCounterResetMinutes() * 60_000L));
        DataSource.FailureStateResult source = dataSource.readFailureState(sourceFailureKey(key), now,
            Math.max(60_000L, config.tempbanCounterResetMinutes() * 60_000L));
        return !account.successful() || !source.successful()
            || account.bannedUntil() > now || source.bannedUntil() > now;
    }

    private void clearFailure(String key) {
        dataSource.clearFailureState(sharedFailureKey(key));
        captchas.remove(key);
    }

    private static String sharedFailureKey(String localKey) {
        if (localKey == null || localKey.isBlank()) return "auth|unknown|unknown";
        return "auth|" + localKey;
    }

    private static String sourceFailureKey(String localKey) {
        if (localKey == null) return "ip|unknown";
        int separator = localKey.lastIndexOf('|');
        String ip = separator < 0 ? localKey : localKey.substring(separator + 1);
        return "ip|" + normalizeIp(ip);
    }

    private boolean validPassword(String password) {
        return password != null && password.length() <= MAX_PASSWORD_LENGTH
            && password.length() >= config.minPasswordLength()
            && password.length() <= config.maxPasswordLength()
            && passwordPattern != null && passwordPattern.matcher(password).matches();
    }

    private boolean validEmail(String value) {
        if (!EmailAddressPolicy.isValid(value)) return false;
        int at = value.lastIndexOf('@');
        if (at <= 0 || at >= value.length() - 1) return false;
        String domain = value.substring(at + 1).toLowerCase(Locale.ROOT);
        for (String blocked : config.emailBlacklist()) {
            if (!blocked.isBlank() && domain.equalsIgnoreCase(blocked.trim())) return false;
        }
        if (!config.emailWhitelist().isEmpty()) {
            boolean allowed = config.emailWhitelist().stream()
                .filter(item -> item != null && !item.isBlank())
                .anyMatch(item -> domain.equalsIgnoreCase(item.trim()));
            if (!allowed) return false;
        }
        return true;
    }

    private String normalizeName(String rawName) {
        if (rawName == null) return null;
        String name = rawName.trim();
        int maximum = Math.min(MAX_NAME_LENGTH, Math.max(config.minNicknameLength(), config.maxNicknameLength()));
        if (name.length() < config.minNicknameLength() || name.length() > maximum
            || nicknamePattern == null || !nicknamePattern.matcher(name).matches()) return null;
        return name.toLowerCase(Locale.ROOT);
    }

    private boolean caseMatches(PlayerAuth auth, String rawName) {
        if (!config.preventOtherCase() || auth == null || auth.getRealName() == null) return true;
        return auth.getRealName().equals(rawName == null ? "" : rawName.trim());
    }

    private AccountResult acquireLogin(String name, String ip, boolean session) {
        DataSource.LoginStateResult result = dataSource.acquireLoginState(name, ip,
            System.currentTimeMillis(), session, config.maxLoginPerIp());
        if (result.status() == DataSource.LoginStateStatus.LIMIT_REACHED) {
            return AccountResult.LOGIN_LIMIT;
        }
        if (!result.acquired()) return AccountResult.DATABASE_ERROR;
        loginLeases.put(name, result.version());
        return AccountResult.SUCCESS;
    }

    /** UI-only hint; the authoritative quota check remains inside acquireLoginState. */
    private boolean loginLimitAllowsSnapshot(PlayerAuth auth, String ip) {
        int limit = config.maxLoginPerIp();
        if (limit <= 0 || "unknown".equals(ip)) return true;
        DataSource.CountResult count = dataSource.countLoggedByIp(ip);
        if (!count.successful()) return false;
        int otherLogged = count.count();
        if (auth != null && auth.isLogged() && ip.equals(normalizeIp(auth.getLastIp()))) {
            otherLogged = Math.max(0, otherLogged - 1);
        }
        return otherLogged < limit;
    }

    private static Pattern compileInputPattern(String expression, String label) {
        String value = expression == null || expression.isBlank() ? ".*" : expression;
        if (value.length() > 2048) {
            throw new IllegalStateException("AuthMe " + label + " validation pattern is too long");
        }
        try {
            return Pattern.compile(value);
        } catch (PatternSyntaxException exception) {
            throw new IllegalStateException("Invalid AuthMe " + label + " validation pattern", exception);
        }
    }

    private static boolean matchesRestrictedPattern(String value, String expression) {
        if (value == null || expression == null || expression.isBlank() || expression.length() > 1024) {
            return false;
        }
        if (expression.regionMatches(true, 0, "regex:", 0, 6)) {
            try {
                return Pattern.compile(expression.substring(6), Pattern.CASE_INSENSITIVE)
                    .matcher(value).matches();
            } catch (PatternSyntaxException ignored) {
                return false;
            }
        }
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < expression.length(); i++) {
            char c = expression.charAt(i);
            if (c == '*') regex.append(".*");
            else regex.append(Pattern.quote(String.valueOf(c)));
        }
        return Pattern.compile(regex.append('$').toString(), Pattern.CASE_INSENSITIVE)
            .matcher(value).matches();
    }

    private static String normalizeIp(String ip) {
        if (ip == null || ip.isBlank()) return "unknown";
        String value = ip.trim();
        return value.length() <= MAX_IP_LENGTH ? value : value.substring(0, MAX_IP_LENGTH);
    }

    private static DataSource createDataSource(DbSettings settings) throws SQLException {
        return switch (settings.backend) {
            case MYSQL -> new MySQLDataSource(settings);
            case MARIADB -> new MariaDBDataSource(settings);
            case POSTGRESQL -> new PostgreSqlDataSource(settings);
            case SQLITE -> new SQLiteDataSource(settings);
        };
    }

    public enum AccountResult {
        SUCCESS,
        ALREADY_REGISTERED,
        NOT_REGISTERED,
        WRONG_PASSWORD,
        TOTP_REQUIRED,
        WRONG_TOTP,
        TOTP_NOT_ENABLED,
        TOTP_ALREADY_ENABLED,
        CAPTCHA_REQUIRED,
        CAPTCHA_INVALID,
        SESSION_INVALID,
        PREMIUM_UNAVAILABLE,
        PREMIUM_MISMATCH,
        LOGIN_LIMIT,
        STALE_CONNECTION,
        REGISTRATION_DISABLED,
        REGISTRATION_LIMIT,
        PASSWORD_MISMATCH,
        UNSAFE_PASSWORD,
        EMAIL_INVALID,
        EMAIL_MISMATCH,
        EMAIL_LIMIT,
        EMAIL_NOT_CONFIGURED,
        EMAIL_SEND_FAILED,
        EMAIL_VERIFICATION_SENT,
        EMAIL_RECOVERY_SENT,
        EMAIL_CODE_INVALID,
        EMAIL_CONFIRMED,
        EMAIL_ADDED,
        EMAIL_CHANGED,
        RATE_LIMITED,
        INVALID_INPUT,
        DATABASE_ERROR,
        CONFIG_ERROR,
        PURGE_CONFIRMATION_REQUIRED
    }

    public record TotpResult(AccountResult result, String secret) { }

    private static final class CaptchaState {
        private final String code;
        private final long expiresAt;

        private CaptchaState(String code, long expiresAt) {
            this.code = code;
            this.expiresAt = expiresAt;
        }
    }

}
