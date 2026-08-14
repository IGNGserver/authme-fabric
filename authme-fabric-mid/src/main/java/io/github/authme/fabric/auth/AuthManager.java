package io.github.authme.fabric.auth;

import io.github.authme.fabric.AuthMe;
import io.github.authme.fabric.antibot.AntiBotManager;
import io.github.authme.fabric.config.AuthMeConfig;
import io.github.authme.fabric.config.SpawnLocation;
import io.github.authme.fabric.config.SpawnStore;
import io.github.authme.fabric.config.EventCommands;
import io.github.authme.fabric.config.WelcomeMessage;
import io.github.authme.fabric.converter.Converter;
import io.github.authme.fabric.converter.Converters;
import io.github.authme.fabric.datasource.DataSource;
import io.github.authme.fabric.datasource.PlayerAuth;
import io.github.authme.fabric.security.PasswordSecurity;
import io.github.authme.fabric.security.RandomStringUtils;
import io.github.authme.fabric.security.HashedPassword;
import io.github.authme.fabric.totp.TotpProvider;
import io.github.authme.fabric.util.Log;
import io.github.authme.fabric.util.MinecraftText;
import io.github.authme.fabric.util.BanListBridge;
import io.github.authme.fabric.util.ProxyProtocol;
import io.github.authme.fabric.util.PurgeFileCleaner;
import io.github.authme.fabric.util.PermissionBridge;
import io.github.authme.fabric.network.JoinLeaveMessageBridge;
import io.github.authme.fabric.mail.EmailSender;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.network.protocol.game.ClientboundPlayerInfoRemovePacket;
import net.minecraft.network.protocol.game.ClientboundPlayerInfoUpdatePacket;
import net.minecraft.world.phys.Vec3;
import net.minecraft.world.level.GameType;
import net.minecraft.world.effect.MobEffectInstance;
import net.minecraft.world.effect.MobEffects;
import net.fabricmc.loader.api.FabricLoader;

import java.util.Locale;
import java.util.Map;
import java.util.List;
import java.util.EnumSet;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * Core authentication logic. Tracks per-player in-memory sessions and persists state to the
 * AuthMe-shaped database, so a shared database works across this fabric port and the original plugin.
 *
 * <p>DB reads are performed off the main thread; results are applied on the next main-thread tick
 * via {@link MinecraftServer#execute(Runnable)}.
 */
public final class AuthManager {

    private final AuthMe auth;
    private final java.util.Map<String, PlayerSession> sessions = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, EmailChallenge> emailChallenges = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, LoginFailure> loginFailures = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.Set<String> unsafeIpBlocks = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final SecureRandom secureRandom = new SecureRandom();
    private final SpawnStore spawnStore;
    private final EventCommands eventCommands;
    private final java.util.List<ScheduledCommand> scheduledCommands = new java.util.concurrent.CopyOnWriteArrayList<>();
    private long tickCounter;
    private boolean autoPurgeStarted;
    private long lastAutoBackupMillis;

    private static final class LoginFailure {
        long windowStarted;
        int attempts;
        long bannedUntil;
    }

    private record RegistrationCheck(DataSource.CheckResult availability, DataSource.CountResult byIp,
                                     DataSource.CountResult byEmail) { }
    private record PurgeResult(DataSource.OperationResult operation, List<PlayerAuth> candidates, int files) { }

    public AuthManager(AuthMe auth) {
        this.auth = auth;
        this.spawnStore = new SpawnStore(auth.config().configDir());
        this.eventCommands = new EventCommands(auth.config().configDir());
    }

    /** Refreshes file-backed command configuration without discarding online sessions. */
    public void reloadConfiguration() {
        eventCommands.load();
        scheduledCommands.clear();
        autoPurgeStarted = false;
        lastAutoBackupMillis = 0L;
    }

    private AuthMeConfig cfg() { return auth.config(); }
    private DataSource ds() { return auth.dataSource(); }
    private PasswordSecurity sec() { return auth.passwordSecurity(); }

    // ===================================================================== join / quit

    public void onJoin(ServerPlayer player) {
        JoinLeaveMessageBridge.prepareJoin(player);
        String joinIp = ip(player);
        if (isTempBanned(joinIp)) {
            kick(player, auth.message("account_tempban"));
            return;
        }
        AntiBotManager ab = auth.antiBot();
        if (ab != null && ab.shouldBlockNewJoins()) {
            kick(player, auth.message("account_tempban"));
            return;
        }

        String name = realName(player);
        applyConfiguredGameMode(player, false);
        if (cfg().protectionEnabled() && cfg().protectionRegistered() && !countryAllowed(player, joinIp)) {
            kick(player, auth.message("country_banned"));
            return;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        if (cfg().allowRestrictedUsers()) {
            String restrictedKey = restrictedKey(name, joinIp);
            if (cfg().banUnsafeIp() && unsafeIpBlocks.contains(restrictedKey)) {
                kick(player, auth.message("restricted_user"));
                return;
            }
            if (!restrictedIpAllowed(name, joinIp)) {
                // Scope the temporary block to the restricted username as well as the address;
                // one failed attempt must not deny every player behind a shared/NAT address.
                if (cfg().banUnsafeIp()) unsafeIpBlocks.add(restrictedKey);
                kick(player, auth.message("restricted_user"));
                return;
            }
        }
        if (!validNickname(name)) {
            kick(player, auth.message("invalid_name", "player", name));
            return;
        }
        if (hasReachedMaxJoinPerIp(joinIp)) {
            kick(player, auth.message("login.sameIp"));
            return;
        }
        PlayerSession session = new PlayerSession(player.getUUID(), lower);
        session.lastIp = joinIp;
        session.joinTime = System.currentTimeMillis();
        session.frozenX = player.getX();
        session.frozenY = player.getY();
        session.frozenZ = player.getZ();
        session.frozenWorld = worldKey(player);
        sessions.put(lower, session);
        player.setInvulnerable(true);
        player.setDeltaMovement(Vec3.ZERO);
        setBlindEffect(player, true);

        if (cfg().unrestrictedNames().stream().map(s -> s.toLowerCase(Locale.ROOT)).anyMatch(lower::equals)) {
            session.accountResolved = true;
            session.registered = true;
            session.authenticated = true;
            applyConfiguredGameMode(player, true);
            player.setInvulnerable(false);
            setBlindEffect(player, false);
            runEventCommands("onJoin", player);
            runEventCommands("onLogin", player);
            JoinLeaveMessageBridge.onAuthenticated(player);
            return;
        }
        if (cfg().hideTablist()) hideTabEntry(player);

        if (ab != null && ab.notifyJoin(session.lastIp)) runAntiBotCommands(player);

        CompletableFuture
            .supplyAsync(() -> ds().lookupAuth(lower))
            .thenAccept(result -> executeMain(() -> {
                if (!result.successful()) {
                    failDatabase(player, session);
                    return;
                }
                applyJoin(player, lower, session, result.auth());
            }))
            .exceptionally(error -> { executeMain(() -> failDatabase(player, session)); return null; });
    }

    private void applyJoin(ServerPlayer player, String lower, PlayerSession session, PlayerAuth authRow) {
        if (offline(player)) return;
        session.accountResolved = true;
        session.registered = (authRow != null);
        if (authRow != null && cfg().preventOtherCase()) {
            String storedRealName = authRow.getRealName();
            if (storedRealName == null || storedRealName.isBlank() || "Player".equals(storedRealName)) {
                CompletableFuture.runAsync(() -> ds().updateRealName(lower, realName(player)));
            } else if (!storedRealName.equals(realName(player))) {
                kick(player, auth.message("invalid_name_case", "valid", storedRealName,
                    "invalid", realName(player)));
                return;
            }
        }
        if (authRow == null && cfg().protectionEnabled() && !cfg().protectionRegistered()
            && !countryAllowed(player, session.lastIp)) {
            kick(player, auth.message("country_banned"));
            return;
        }
        runEventCommands("onJoin", player);
        if (!cfg().noTeleport() && cfg().teleportUnauthenticatedToSpawn()) teleportToConfiguredSpawn(player, authRow == null);
        if (authRow == null) {
            if (!cfg().registrationEnabled() || cfg().kickNonRegistered()) {
                kick(player, auth.message("unknown_user"));
                return;
            }
            if (!cfg().registrationForce()) {
                player.setInvulnerable(false);
                if (cfg().captchaEnabled() && cfg().captchaForRegistration()) requireCaptcha(session);
                schedulePrompt(player, session, false);
                return;
            }
            if (cfg().captchaEnabled() && cfg().captchaForRegistration()) requireCaptcha(session);
            schedulePrompt(player, session, false);
            return;
        }
        session.lastLogin = authRow.getLastLogin() == null ? 0L : authRow.getLastLogin();

        if (cfg().captchaEnabled() && failureAttempts(session.lastIp) >= cfg().maxLoginTriesForCaptcha()) {
            requireCaptcha(session);
        }

        boolean autoLogin = false;
        if (cfg().enablePremium() && auth.server() != null && auth.server().usesAuthentication()
            && authRow.getPremiumUuid() != null
            && authRow.getPremiumUuid().equals(player.getUUID())) {
            autoLogin = true;
        } else if (cfg().sessionEnabled() && authRow.hasSession()) {
            long now = System.currentTimeMillis();
            long timeout = cfg().sessionTimeoutMinutes() * 60_000L;
            boolean within = session.lastLogin > 0 && (now - session.lastLogin) <= timeout;
            boolean ipOk = !(cfg().sessionOnlyIp() || cfg().sessionExpireOnIpChange())
                || (authRow.getLastIp() != null && authRow.getLastIp().equalsIgnoreCase(session.lastIp));
            if (within && ipOk) autoLogin = true;
        }

        if (autoLogin) {
            completeLogin(player, session, authRow,
                () -> { runEventCommands("onSessionLogin", player); MinecraftText.send(player, auth.message("login.success_session")); });
        } else {
            schedulePrompt(player, session, true);
        }
    }

    public void onDisconnect(ServerPlayer player) {
        JoinLeaveMessageBridge.clear(player);
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.remove(lower);
        emailChallenges.remove("verify:" + lower);
        emailChallenges.remove("recover:" + lower);
        if (session == null) return;
        session.active = false;
        session.loginGeneration++;
        if (session.authenticated) {
            double x = player.getX(), y = player.getY(), z = player.getZ();
            float yaw = player.getYRot(), pitch = player.getXRot();
            String world = worldKey(player);
            runEventCommands("onLogout", player);
            auth.emitProxyMessage(ProxyProtocol.LOGOUT, lower);
            CompletableFuture.runAsync(() -> {
                boolean ok = ds().persistDisconnect(lower, System.currentTimeMillis(), x, y, z, yaw, pitch, world,
                    cfg().saveQuitLocation(), cfg().sessionEnabled());
                if (!ok) Log.error("Failed to persist disconnect state for " + lower);
            }).whenComplete((r, e) -> { if (e != null) Log.error("Failed to flush session for " + lower, e); });
        }
    }

    // ===================================================================== register / login

    public void login(ServerPlayer player, String password) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || session.authenticated) {
            MinecraftText.send(player, auth.message("login.already"));
            return;
        }
        if (session.captchaPending) {
            MinecraftText.send(player, auth.message("captcha.required", "code", session.captchaCode));
            return;
        }
        if (hasReachedMaxLoginPerIp(session.lastIp, lower)) {
            MinecraftText.send(player, auth.message("login.sameIp"));
            return;
        }
        CompletableFuture
            .supplyAsync(() -> ds().lookupAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (offline(player)) return;
                if (!a.successful()) {
                    failDatabase(player, session);
                    return;
                }
                if (a.auth() == null) {
                    MinecraftText.send(player, auth.message("login.notRegistered"));
                    return;
                }
                PlayerAuth row = a.auth();
                HashedPassword stored = row.toHashedPassword();
                PasswordSecurity.VerificationResult result = sec().verify(password, stored, lower);

                if (result == null) {
                    onWrongPassword(player, session, lower);
                    return;
                }
                if (result.isLegacy()) {
                    // re-hash with the primary algorithm
                    HashedPassword rehashed = sec().computeHash(password, lower);
                    CompletableFuture.supplyAsync(() -> ds().updatePassword(lower, rehashed))
                        .thenAccept(updated -> { if (!updated) Log.error("Could not persist legacy password migration for " + lower); });
                    Log.info("Rehashed legacy password for " + lower);
                }
                session.loginAttempts = 0;
                session.totpKey = row.getTotpKey();
                if (row.getTotpKey() != null && !row.getTotpKey().isEmpty()
                    && TotpProvider.isPlausibleSecret(row.getTotpKey())) {
                    session.pendingTotp = true;
                    session.captchaPending = false;
                    MinecraftText.send(player, auth.message("totp.required"));
                } else {
                    completeLogin(player, session, row, null);
                }
            }))
            .exceptionally(error -> { executeMain(() -> failDatabase(player, session)); return null; });
    }

    /** Completes a login requested by a HMAC-authenticated AuthMe proxy. */
    public void forceLoginFromProxy(ServerPlayer player, UUID verifiedPremiumUuid) {
        if (!cfg().bungeecordHook() || player == null) return;
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || session.authenticated) return;
        CompletableFuture.supplyAsync(() -> ds().lookupAuth(lower))
            .thenAccept(result -> executeMain(() -> {
                if (offline(player) || session != sessions.get(lower)) return;
                if (!result.successful()) { failDatabase(player, session); return; }
                PlayerAuth row = result.auth();
                if (row == null) { Log.warn("Rejected proxy login for unregistered account " + lower); return; }
                if (verifiedPremiumUuid != null && !verifiedPremiumUuid.equals(row.getPremiumUuid())) {
                    Log.warn("Rejected proxy premium login for " + lower + ": UUID does not match the stored account");
                    return;
                }
                completeLogin(player, session, row, () -> auth.emitProxyMessage(ProxyProtocol.PERFORM_LOGIN_ACK, lower));
            }))
            .exceptionally(error -> { executeMain(() -> failDatabase(player, session)); return null; });
    }

    private void onWrongPassword(ServerPlayer player, PlayerSession session, String lower) {
        MinecraftText.send(player, auth.message("login.wrong"));
        session.loginAttempts = recordLoginFailure(session.lastIp);
        if (cfg().kickOnWrongPassword()) {
            kick(player, auth.message("login.wrong"));
        } else if (cfg().tempbanEnabled() && session.loginAttempts >= cfg().tempbanMaxLoginTries()) {
            applyTempban(player, session.lastIp);
            kick(player, auth.message("account_tempban"));
            Log.info("Temporarily blocked repeated login failures for " + lower + ".");
        } else if (cfg().captchaEnabled() && session.loginAttempts >= cfg().maxLoginTriesForCaptcha()) {
            session.captchaPending = true;
            session.captchaCode = RandomStringUtils.generateNum(Math.max(3, cfg().captchaLength()));
            MinecraftText.send(player, auth.message("captcha.required", "code", session.captchaCode));
        }
    }

    /** Dispatches the AuthMe-compatible registration modes from the first and optional second argument. */
    public void register(ServerPlayer player, String first, String second) {
        if (cfg().registrationType() == io.github.authme.fabric.config.RegistrationType.EMAIL) {
            registerByEmail(player, first, second);
        } else {
            registerByPassword(player, first, second);
        }
    }

    private void registerByPassword(ServerPlayer player, String password, String second) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null) return;
        session.dialogShown = false;
        if (session.authenticated) {
            MinecraftText.send(player, auth.message("already_logged_in"));
            return;
        }
        if (!cfg().registrationEnabled()) {
            MinecraftText.send(player, auth.message("reg.disabled"));
            return;
        }
        if (session.captchaPending) {
            MinecraftText.send(player, auth.message("captcha.required", "code", session.captchaCode));
            return;
        }
        io.github.authme.fabric.config.RegisterSecondaryArgument secondArg = cfg().registrationSecondArgument();
        String email = null;
        if (secondArg == io.github.authme.fabric.config.RegisterSecondaryArgument.CONFIRMATION) {
            if (second == null) {
                MinecraftText.send(player, auth.message("reg.usage"));
                return;
            }
            if (!password.equals(second)) {
                MinecraftText.send(player, auth.message("reg.noMatch"));
                return;
            }
        } else if (secondArg == io.github.authme.fabric.config.RegisterSecondaryArgument.EMAIL_MANDATORY
            || secondArg == io.github.authme.fabric.config.RegisterSecondaryArgument.EMAIL_OPTIONAL) {
            if (second == null) {
                if (secondArg == io.github.authme.fabric.config.RegisterSecondaryArgument.EMAIL_MANDATORY) {
                    MinecraftText.send(player, auth.message("reg.usage"));
                    return;
                }
            } else {
                email = second.trim();
                if (!validEmailDomain(email)) {
                    MinecraftText.send(player, auth.message("email.invalid"));
                    return;
                }
            }
        }
        if (!validPassword(password)) {
            MinecraftText.send(player, auth.message("reg.usage"));
            return;
        }
        if (cfg().unsafePasswords().contains(password.toLowerCase(Locale.ROOT))) {

            MinecraftText.send(player, auth.message("reg.unsafePassword"));
            return;
        }
        final String registrationEmail = email;
        CompletableFuture
            .supplyAsync(() -> new RegistrationCheck(ds().checkAuthAvailable(lower),
                ds().countRegisteredByIp(session.lastIp),
                registrationEmail == null ? new DataSource.CountResult(0, true) : ds().countRegisteredByEmail(registrationEmail)))
            .thenAccept(check -> executeMain(() -> {
                if (offline(player)) return;
                if (!check.availability().successful() || !check.byIp().successful() || !check.byEmail().successful()) {
                    MinecraftText.send(player, auth.message("database.error"));
                    return;
                }
                if (check.availability().available()) {
                    MinecraftText.send(player, auth.message("reg.already"));
                    return;
                }
                if (cfg().maxRegistrationsPerIp() > 0
                    && check.byIp().count() >= cfg().maxRegistrationsPerIp()) {
                    MinecraftText.send(player, auth.message("reg.maxIp"));
                    return;
                }
                if (registrationEmail != null && cfg().maxRegistrationsPerEmail() > 0
                    && check.byEmail().count() >= cfg().maxRegistrationsPerEmail()) {
                    MinecraftText.send(player, auth.message("email.max"));
                    return;
                }
                HashedPassword hp = sec().computeHash(password, lower);
                PlayerAuth pa = PlayerAuth.builder()
                    .name(lower)
                    .realName(realName(player))
                    .password(hp.getHash(), hp.getSalt())
                    .lastIp(session.lastIp)
                    .registrationDate(System.currentTimeMillis())
                    .registrationIp(session.lastIp)
                    .email(registrationEmail)
                    .locX(session.frozenX)
                    .locY(session.frozenY)
                    .locZ(session.frozenZ)
                    .locWorld(session.frozenWorld)
                    .build();
                CompletableFuture.supplyAsync(() -> ds().saveAuth(pa))
                    .thenAccept(saved -> executeMain(() -> {
                        if (!saved) {
                            MinecraftText.send(player, auth.message("database.error"));
                            return;
                        }
                        finishRegister(player, lower, session, pa);
                    }))
                    .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
            }))
            .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
    }

    private void registerByEmail(ServerPlayer player, String email, String second) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null) return;
        session.dialogShown = false;
        if (session.authenticated) {
            MinecraftText.send(player, auth.message("already_logged_in"));
            return;
        }
        if (!cfg().registrationEnabled()) {
            MinecraftText.send(player, auth.message("reg.disabled"));
            return;
        }
        if (!cfg().emailRegistrationConfigured()) {
            MinecraftText.send(player, auth.message("reg.emailSettings"));
            return;
        }
        if (session.captchaPending) {
            MinecraftText.send(player, auth.message("captcha.required", "code", session.captchaCode));
            return;
        }
        email = email == null ? "" : email.trim();
        if (!validEmailDomain(email)) {
            MinecraftText.send(player, auth.message("email.invalid"));
            return;
        }
        io.github.authme.fabric.config.RegisterSecondaryArgument secondArg = cfg().registrationSecondArgument();
        if (secondArg != io.github.authme.fabric.config.RegisterSecondaryArgument.NONE) {
            if (second == null) {
                MinecraftText.send(player, auth.message("reg.usage"));
                return;
            }
            if (!email.equalsIgnoreCase(second.trim())) {
                MinecraftText.send(player, auth.message("reg.noMatch"));
                return;
            }
        }
        final String registrationEmail = email;
        CompletableFuture
            .supplyAsync(() -> new RegistrationCheck(ds().checkAuthAvailable(lower),
                ds().countRegisteredByIp(session.lastIp), ds().countRegisteredByEmail(registrationEmail)))
            .thenAccept(check -> executeMain(() -> {
                if (offline(player)) return;
                if (!check.availability().successful() || !check.byIp().successful() || !check.byEmail().successful()) {
                    MinecraftText.send(player, auth.message("database.error"));
                    return;
                }
                if (check.availability().available()) {
                    MinecraftText.send(player, auth.message("reg.already"));
                    return;
                }
                if (cfg().maxRegistrationsPerIp() > 0
                    && check.byIp().count() >= cfg().maxRegistrationsPerIp()) {
                    MinecraftText.send(player, auth.message("reg.maxIp"));
                    return;
                }
                if (cfg().maxRegistrationsPerEmail() > 0
                    && check.byEmail().count() >= cfg().maxRegistrationsPerEmail()) {
                    MinecraftText.send(player, auth.message("email.max"));
                    return;
                }
                int length = Math.max(cfg().minPasswordLength(), Math.min(cfg().maxPasswordLength(),
                    cfg().emailGeneratedPasswordLength()));
                String generatedPassword = RandomStringUtils.generate(length);
                HashedPassword hp = sec().computeHash(generatedPassword, lower);
                PlayerAuth pa = PlayerAuth.builder()
                    .name(lower)
                    .realName(realName(player))
                    .password(hp.getHash(), hp.getSalt())
                    .lastIp(session.lastIp)
                    .registrationDate(System.currentTimeMillis())
                    .registrationIp(session.lastIp)
                    .email(registrationEmail)
                    .locX(session.frozenX)
                    .locY(session.frozenY)
                    .locZ(session.frozenZ)
                    .locWorld(session.frozenWorld)
                    .build();
                CompletableFuture.supplyAsync(() -> ds().saveAuth(pa))
                    .thenAccept(saved -> executeMain(() -> {
                        if (!saved) {
                            MinecraftText.send(player, auth.message("database.error"));
                            return;
                        }
                        session.registered = true;
                        CompletableFuture.supplyAsync(() -> EmailSender.send(cfg(), registrationEmail,
                                "Your new AuthMe password",
                                "Your AuthMe account for " + realName(player) + " was created.\n"
                                    + "Your generated password is: " + generatedPassword))
                            .thenAccept(sent -> executeMain(() -> {
                                if (offline(player)) return;
                                MinecraftText.send(player, auth.message(sent ? "reg.emailSuccess" : "reg.emailSendFailure",
                                    "email", registrationEmail));
                                if (sent) runEventCommands("onRegister", player);
                            }));
                    }))
                    .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
            }))
            .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
    }

    private void finishRegister(ServerPlayer player, String lower, PlayerSession session, PlayerAuth pa) {
        executeMain(() -> {
            if (offline(player)) return;
            MinecraftText.send(player, auth.message("reg.success", "?", ""));
            runEventCommands("onRegister", player);
            if (cfg().forceKickAfterRegister()) {
                Runnable kickAction = () -> {
                    if (!offline(player)) kick(player, auth.message("reg.success"));
                };
                if (cfg().registrationKickDelaySeconds() > 0) {
                    java.util.concurrent.CompletableFuture.delayedExecutor(
                        cfg().registrationKickDelaySeconds(), java.util.concurrent.TimeUnit.SECONDS)
                        .execute(() -> executeMain(kickAction));
                } else {
                    kickAction.run();
                }
                return;
            }
            if (cfg().forceLoginAfterRegister()) {
                session.registered = true;
                MinecraftText.send(player, auth.message("reg.loginAfterRegister"));
                return;
            }
            completeLogin(player, session, pa, () -> {
                if (cfg().forcePortalAfterRegister() && !cfg().noTeleport()) {
                    teleportToConfiguredSpawn(player, true);
                }
            });
        });
    }

    public void changePassword(ServerPlayer player, String oldPw, String newPw) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("not_logged_in"));
            return;
        }
        if (!validPassword(newPw)) {
            MinecraftText.send(player, auth.message("reg.usage"));
            return;
        }

        CompletableFuture
            .supplyAsync(() -> ds().lookupAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (!a.successful()) { failDatabase(player, session); return; }
                if (a.auth() == null) { MinecraftText.send(player, auth.message("unknown_user", "player", realName(player))); return; }
                PasswordSecurity.VerificationResult r = sec().verify(oldPw, a.auth().toHashedPassword(), lower);
                if (r == null) { MinecraftText.send(player, auth.message("changepassword.wrong")); return; }
                HashedPassword newHash = sec().computeHash(newPw, lower);
                CompletableFuture.supplyAsync(() -> ds().updatePassword(lower, newHash))
                    .thenAccept(updated -> executeMain(() -> MinecraftText.send(player,
                        auth.message(updated ? "changepassword.success" : "database.error"))))
                    .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
             }))
            .exceptionally(error -> { executeMain(() -> failDatabase(player, session)); return null; });
    }

    public void logout(ServerPlayer player) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("logout.notlogged"));
            return;
        }
        CompletableFuture.supplyAsync(() -> ds().setLoginFlags(lower, false, false))
            .thenAccept(updated -> executeMain(() -> {
                if (!updated) {
                    MinecraftText.send(player, auth.message("database.error"));
                    return;
                }
                session.authenticated = false;
                session.pendingTotp = false;
                runEventCommands("onLogout", player);
                auth.emitProxyMessage(ProxyProtocol.LOGOUT, lower);
                player.setInvulnerable(true);
                MinecraftText.send(player, auth.message("logout.success"));
            }))
            .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
    }

    public void unregister(ServerPlayer player, String password) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null) return;
        CompletableFuture
            .supplyAsync(() -> ds().lookupAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (!a.successful()) { failDatabase(player, session); return; }
                if (a.auth() == null) { MinecraftText.send(player, auth.message("unknown_user", "player", realName(player))); return; }
                PasswordSecurity.VerificationResult r = sec().verify(password, a.auth().toHashedPassword(), lower);
                if (r == null) { MinecraftText.send(player, auth.message("unregister.wrong")); return; }
                CompletableFuture.supplyAsync(() -> ds().removeAuth(lower))
                    .thenAccept(removed -> executeMain(() -> {
                        if (!removed) { MinecraftText.send(player, auth.message("database.error")); return; }
                        sessions.remove(lower);
                        runEventCommands("onUnregister", player);
                        MinecraftText.send(player, auth.message("unregister.success"));
                        kick(player, auth.message("unregister.success"));
                    }))
                    .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
            }))
            .exceptionally(error -> { executeMain(() -> failDatabase(player, session)); return null; });
    }


    // ===================================================================== captcha

    public void captcha(ServerPlayer player, String code) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.captchaPending) {
            MinecraftText.send(player, auth.message("captcha.usage"));
            return;
        }
        if (session.captchaCode.equalsIgnoreCase(code)) {
            session.captchaPending = false;
            session.captchaCode = "";
            session.loginAttempts = 0;
            clearLoginFailures(session.lastIp);
            MinecraftText.send(player, auth.message("captcha.success"));
        } else {
            session.captchaCode = RandomStringUtils.generateNum(Math.max(3, cfg().captchaLength()));
            MinecraftText.send(player, auth.message("captcha.required", "code", session.captchaCode));
        }
    }

    // ===================================================================== 2FA

    public void totpVerify(ServerPlayer player, String code) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.pendingTotp) {
            return;
        }
        if (!TotpProvider.validateCode(session.totpKey, code)) {
            MinecraftText.send(player, auth.message("totp.wrong"));
            return;
        }
        CompletableFuture
            .supplyAsync(() -> ds().lookupAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (!a.successful()) { failDatabase(player, session); return; }
                if (a.auth() == null) return;
                completeLogin(player, session, a.auth(),
                    () -> MinecraftText.send(player, auth.message("totp.success")));
            }))
            .exceptionally(error -> { executeMain(() -> failDatabase(player, session)); return null; });
    }

    public void totpEnable(ServerPlayer player) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("not_logged_in"));
            return;
        }
        CompletableFuture
            .supplyAsync(() -> ds().lookupAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (!a.successful()) { failDatabase(player, session); return; }
                if (a.auth() != null && a.auth().getTotpKey() != null && !a.auth().getTotpKey().isEmpty()) {
                    MinecraftText.send(player, auth.message("totp.already"));
                    return;
                }
                if (!session.pendingTotpSetupKey.isBlank()) {
                    MinecraftText.send(player, auth.message("totp.setup", "key", session.pendingTotpSetupKey));
                    return;
                }
                String secret = TotpProvider.generateSecret();
                session.pendingTotpSetupKey = secret;
                MinecraftText.send(player, auth.message("totp.setup", "key", secret));
                MinecraftText.send(player, "&7" + TotpProvider.otpAuthUri("AuthMe", realName(player), secret));
            }))
            .exceptionally(error -> { executeMain(() -> failDatabase(player, session)); return null; });
    }

    public void totpConfirm(ServerPlayer player, String code) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("not_logged_in"));
            return;
        }
        String secret = session.pendingTotpSetupKey;
        if (secret == null || secret.isBlank()) {
            MinecraftText.send(player, auth.message("totp.notEnabled"));
            return;
        }
        if (!TotpProvider.validateCode(secret, code)) {
            MinecraftText.send(player, auth.message("totp.wrong"));
            return;
        }
        CompletableFuture.supplyAsync(() -> ds().updateTotpKey(lower, secret))
            .thenAccept(updated -> executeMain(() -> {
                if (!updated) { MinecraftText.send(player, auth.message("database.error")); return; }
                session.pendingTotpSetupKey = "";
                MinecraftText.send(player, auth.message("totp.confirmed"));
            }))
            .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
    }

    public void totpDisable(ServerPlayer player, String code) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("not_logged_in"));
            return;
        }
        CompletableFuture
            .supplyAsync(() -> ds().lookupAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (!a.successful()) { failDatabase(player, session); return; }
                if (a.auth() == null || a.auth().getTotpKey() == null || a.auth().getTotpKey().isEmpty()) {
                    MinecraftText.send(player, auth.message("totp.notEnabled"));
                    return;
                }
                if (!TotpProvider.validateCode(a.auth().getTotpKey(), code)) {
                    MinecraftText.send(player, auth.message("totp.wrong"));
                    return;
                }
                CompletableFuture.supplyAsync(() -> ds().updateTotpKey(lower, null))
                    .thenAccept(updated -> executeMain(() -> MinecraftText.send(player,
                        auth.message(updated ? "totp.disabled" : "database.error"))))
                    .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
            }))
            .exceptionally(error -> { executeMain(() -> failDatabase(player, session)); return null; });
    }

    // ===================================================================== premium / email

    public void premiumEnable(ServerPlayer player) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("not_logged_in"));
            return;
        }
        if (!cfg().enablePremium()) {
            MinecraftText.send(player, auth.message("premium.usage"));
            return;
        }
        if (auth.server() == null || !auth.server().usesAuthentication()) {
            MinecraftText.send(player, auth.message("premium.unavailable"));
            return;
        }
        UUID uuid = player.getUUID();
        CompletableFuture.supplyAsync(() -> ds().updatePremiumUuid(lower, uuid))
                    .thenAccept(updated -> executeMain(() -> {
                        MinecraftText.send(player, auth.message(updated ? "premium.set" : "database.error"));
                        if (updated) auth.emitProxyMessage(ProxyProtocol.PREMIUM_SET, lower);
                    }))
            .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
    }

    public void premiumDisable(ServerPlayer player) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("not_logged_in"));
            return;
        }
        CompletableFuture.supplyAsync(() -> ds().updatePremiumUuid(lower, null))
            .thenAccept(updated -> executeMain(() -> {
                MinecraftText.send(player, auth.message(updated ? "premium.removed" : "database.error"));
                if (updated) auth.emitProxyMessage(ProxyProtocol.PREMIUM_UNSET, lower);
            }))
            .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
    }

    /** Applies the premium flag from an administrator command. */
    public void adminPremium(String targetLower, boolean enabled, Consumer<String> reply) {
        if (!cfg().enablePremium()) {
            reply.accept(auth.message("premium.unavailable"));
            return;
        }
        UUID premiumUuid = null;
        if (enabled) {
            PlayerSession targetSession = sessions.get(targetLower);
            ServerPlayer online = targetSession == null ? null : onlinePlayer(targetSession.uuid);
            if (online != null) {
                premiumUuid = online.getUUID();
            } else if (auth.server() != null && auth.server().usesAuthentication()) {
                reply.accept(auth.message("premium.unavailable"));
                return;
            } else {
                premiumUuid = UUID.nameUUIDFromBytes(
                    ("OfflinePlayer:" + targetLower).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
        }
        UUID value = premiumUuid;
        CompletableFuture.supplyAsync(() -> {
            DataSource.LookupResult lookup = ds().lookupAuth(targetLower);
            if (!lookup.successful()) return "database.error";
            if (lookup.auth() == null) return "admin.playerNotFound";
            return ds().updatePremiumUuid(targetLower, value)
                ? (enabled ? "admin.premiumSet" : "admin.premiumRemoved") : "database.error";
        }).thenAccept(key -> executeMain(() -> {
                if ("admin.premiumSet".equals(key) || "admin.premiumRemoved".equals(key)) {
                    auth.emitProxyMessage(enabled ? ProxyProtocol.PREMIUM_SET : ProxyProtocol.PREMIUM_UNSET, targetLower);
                }
                reply.accept(auth.message(key, "player", targetLower));
            }))
            .exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    public void emailAdd(ServerPlayer player, String email, String verify) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("not_logged_in"));
            return;
        }
        if (email == null || !validEmailDomain(email) || !email.equals(verify)) {
            if (!java.util.Objects.equals(email, verify)) {
                MinecraftText.send(player, auth.message("email.noMatch"));
            } else {
                MinecraftText.send(player, auth.message("email.invalid"));
            }
            return;
        }
        if (cfg().emailRequireVerification()) {
            if (!cfg().emailEnabled()) {
                MinecraftText.send(player, auth.message("email.recoveryDisabled"));
                return;
            }
            String code = recoveryCode();
            EmailChallenge challenge = new EmailChallenge(email, code,
                System.currentTimeMillis() + cfg().emailRecoveryTimeoutSeconds() * 1000L, false);
            emailChallenges.put("verify:" + lower, challenge);
            CompletableFuture.supplyAsync(() -> EmailSender.send(cfg(), email, "AuthMe e-mail verification",
                    "Your AuthMe verification code is: " + code + "\nIt expires in "
                        + (cfg().emailRecoveryTimeoutSeconds() / 60) + " minutes."))
                .thenAccept(sent -> executeMain(() -> {
                    if (!sent) {
                        emailChallenges.remove("verify:" + lower);
                        MinecraftText.send(player, auth.message("database.error"));
                    } else {
                        MinecraftText.send(player, auth.message("email.verifySent"));
                    }
                }))
                .exceptionally(error -> { executeMain(() -> {
                    emailChallenges.remove("verify:" + lower);
                    MinecraftText.send(player, auth.message("database.error"));
                }); return null; });
            return;
        }
        CompletableFuture.supplyAsync(() -> {
            DataSource.CountResult count = ds().countRegisteredByEmail(email);
            if (!count.successful()) return "database.error";
            if (cfg().maxRegistrationsPerEmail() > 0 && count.count() >= cfg().maxRegistrationsPerEmail()) return "email.max";
            return ds().updateEmail(lower, email) ? "email.added" : "database.error";
        })
            .thenAccept(key -> executeMain(() -> MinecraftText.send(player, auth.message(key))))
            .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
    }

    public void emailChange(ServerPlayer player, String oldEmail, String newEmail) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) { MinecraftText.send(player, auth.message("not_logged_in")); return; }
        if (!validEmailDomain(oldEmail) || !validEmailDomain(newEmail)) { MinecraftText.send(player, auth.message("email.invalid")); return; }
        String oldValue = oldEmail.trim(), newValue = newEmail.trim();
        if (oldValue.equalsIgnoreCase(newValue)) { MinecraftText.send(player, auth.message("email.noMatch")); return; }
        CompletableFuture.supplyAsync(() -> {
            DataSource.LookupResult lookup = ds().lookupAuth(lower);
            if (!lookup.successful()) return "database.error";
            if (lookup.auth() == null || lookup.auth().getEmail() == null || !oldValue.equalsIgnoreCase(lookup.auth().getEmail())) return "email.invalid";
            DataSource.CountResult count = ds().countRegisteredByEmail(newValue);
            if (!count.successful()) return "database.error";
            if (cfg().maxRegistrationsPerEmail() > 0 && count.count() >= cfg().maxRegistrationsPerEmail()) return "email.max";
            return "ok";
        }).thenAccept(result -> executeMain(() -> {
            if (!"ok".equals(result)) { MinecraftText.send(player, auth.message(result)); return; }
            if (cfg().emailRequireVerification()) {
                if (!cfg().emailEnabled()) { MinecraftText.send(player, auth.message("email.recoveryDisabled")); return; }
                String code = recoveryCode();
                emailChallenges.put("verify:" + lower, new EmailChallenge(newValue, code, System.currentTimeMillis() + cfg().emailRecoveryTimeoutSeconds() * 1000L, false));
                CompletableFuture.supplyAsync(() -> EmailSender.send(cfg(), newValue, "AuthMe e-mail verification", "Your AuthMe verification code is: " + code))
                    .thenAccept(sent -> executeMain(() -> MinecraftText.send(player, auth.message(sent ? "email.verifySent" : "database.error"))));
            } else CompletableFuture.supplyAsync(() -> ds().updateEmail(lower, newValue))
                .thenAccept(updated -> executeMain(() -> MinecraftText.send(player, auth.message(updated ? "email.changed" : "database.error"))));
        })).exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
    }

    public void emailRecover(ServerPlayer player, String email) {
        if (!cfg().emailEnabled()) {
            MinecraftText.send(player, auth.message("email.recoveryDisabled"));
            return;
        }
        if (email == null || !validEmailDomain(email)) {
            MinecraftText.send(player, auth.message("email.invalid"));
            return;
        }
        String lower = realName(player).toLowerCase(Locale.ROOT);
        CompletableFuture.supplyAsync(() -> ds().getAuthByEmail(email.trim()))
            .thenAccept(account -> executeMain(() -> {
                if (account == null || account.getName() == null || !account.getName().equalsIgnoreCase(lower)
                    || account.getEmail() == null || !account.getEmail().equalsIgnoreCase(email.trim())) {
                    // Do not disclose whether an address is registered.
                    MinecraftText.send(player, auth.message("email.recoverySent"));
                    return;
                }
                String code = recoveryCode();
                EmailChallenge challenge = new EmailChallenge(account.getEmail(), code,
                    System.currentTimeMillis() + cfg().emailRecoveryTimeoutSeconds() * 1000L, true);
                emailChallenges.put("recover:" + lower, challenge);
                CompletableFuture.supplyAsync(() -> EmailSender.send(cfg(), account.getEmail(),
                    "AuthMe password recovery", "Your AuthMe recovery code is: " + code
                        + "\nIt expires in " + (cfg().emailRecoveryTimeoutSeconds() / 60) + " minutes."))
                    .thenAccept(sent -> executeMain(() -> {
                        if (!sent) {
                            emailChallenges.remove("recover:" + lower);
                            // Keep recovery responses indistinguishable even when SMTP fails.
                            MinecraftText.send(player, auth.message("email.recoverySent"));
                        } else {
                            MinecraftText.send(player, auth.message("email.recoverySent"));
                        }
                    }));
            }))
            .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("email.recoverySent"))); return null; });
    }

    public void emailConfirm(ServerPlayer player, String code) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        EmailChallenge recovery = emailChallenges.get("recover:" + lower);
        EmailChallenge verification = emailChallenges.get("verify:" + lower);
        EmailChallenge challenge = recovery != null ? recovery : verification;
        boolean valid = challenge != null && challenge.expiresAt >= System.currentTimeMillis()
            && constantTimeEquals(challenge.code, code);
        if (!valid) {
            if (challenge != null && ++challenge.failedAttempts >= 5) {
                emailChallenges.remove(challenge.recovery ? "recover:" + lower : "verify:" + lower, challenge);
            }
            MinecraftText.send(player, auth.message(recovery != null ? "email.recoveryCodeWrong" : "email.verifyWrong"));
            return;
        }
        if (challenge.recovery) {
            challenge.verified = true;
            MinecraftText.send(player, auth.message("email.recoveryCode"));
        } else {
            CompletableFuture.supplyAsync(() -> {
                DataSource.CountResult count = ds().countRegisteredByEmail(challenge.email);
                if (!count.successful()) return "database.error";
                if (cfg().maxRegistrationsPerEmail() > 0 && count.count() >= cfg().maxRegistrationsPerEmail()) return "email.max";
                return ds().updateEmail(lower, challenge.email) ? "email.verified" : "database.error";
            }).thenAccept(key -> executeMain(() -> {
                    if (!"email.verified".equals(key)) { MinecraftText.send(player, auth.message(key)); return; }
                    challenge.verified = true;
                    emailChallenges.remove("verify:" + lower);
                    MinecraftText.send(player, auth.message(key));
                }))
                .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });

        }
    }

    public void emailSetRecoveredPassword(ServerPlayer player, String password) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        EmailChallenge challenge = emailChallenges.get("recover:" + lower);
        PlayerSession session = sessions.get(lower);
        if (challenge == null || !challenge.recovery || !challenge.verified
            || challenge.expiresAt < System.currentTimeMillis()) {
            MinecraftText.send(player, auth.message("email.recoveryCodeWrong"));
            return;
        }
        if (!validPassword(password)) {
            MinecraftText.send(player, auth.message("reg.usage"));
            return;
        }
        HashedPassword hash = sec().computeHash(password, lower);
        CompletableFuture.supplyAsync(() -> ds().updatePassword(lower, hash) ? ds().lookupAuth(lower) : null)
            .thenAccept(result -> executeMain(() -> {
                if (result == null || !result.successful() || result.auth() == null || session == null) {
                    MinecraftText.send(player, auth.message("database.error"));
                    return;
                }
                emailChallenges.remove("recover:" + lower);
                session.registered = true;
                completeLogin(player, session, result.auth(),
                    () -> MinecraftText.send(player, auth.message("email.recoveryPassword")));
            }))
            .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
    }

    private String recoveryCode() {
        return String.format(Locale.ROOT, "%08d", secureRandom.nextInt(100_000_000));
    }

    private static boolean constantTimeEquals(String left, String right) {
        if (left == null || right == null) return false;
        return java.security.MessageDigest.isEqual(left.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
            right.trim().getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    public void emailShow(ServerPlayer player) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        CompletableFuture
            .supplyAsync(() -> ds().lookupAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (!a.successful()) { MinecraftText.send(player, auth.message("database.error")); return; }
                if (a.auth() == null) { MinecraftText.send(player, auth.message("unknown_user", "player", realName(player))); return; }
                MinecraftText.send(player, auth.message("email.show", "email", a.auth().getEmail() == null ? "" : a.auth().getEmail()));
            }))
            .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
    }

    // ===================================================================== admin

    public void adminRegister(String targetLower, String password, Runnable onComplete) {
        HashedPassword hp = sec().computeHash(password, targetLower);
        PlayerAuth pa = PlayerAuth.builder()

            .name(targetLower)
            .realName(targetLower)
            .password(hp.getHash(), hp.getSalt())
            .lastIp("")
            .registrationDate(System.currentTimeMillis())
            .registrationIp("")
            .locX(0).locY(0).locZ(0).locWorld("minecraft:overworld")
            .build();
        CompletableFuture.runAsync(() -> {
            boolean saved = ds().saveAuth(pa);
            PlayerSession online = sessions.get(targetLower);
            if (online != null && saved) {
                online.registered = true;
            }
            if (saved) {
                executeMain(onComplete);
            } else if (online != null) {
                executeMain(() -> notifyDatabaseError(online.uuid));
            }
        });
    }

    public void adminUnregister(String targetLower, Runnable onComplete) {
        CompletableFuture.runAsync(() -> {
            boolean removed = ds().removeAuth(targetLower);
            PlayerSession online = sessions.get(targetLower);
            if (online != null && removed) {
                online.authenticated = false;
                executeMain(() -> {
                    net.minecraft.server.level.ServerPlayer p = onlinePlayer(online.uuid);
                    if (p != null) kick(p, auth.message("unregister.success"));
                });
            }
            if (removed) {
                executeMain(onComplete);
            } else if (online != null) {
                executeMain(() -> notifyDatabaseError(online.uuid));
            }
        });
    }

    public void adminSetPassword(String targetLower, String password, Runnable onComplete) {
        HashedPassword hp = sec().computeHash(password, targetLower);
        CompletableFuture.runAsync(() -> {
            boolean updated = ds().updatePassword(targetLower, hp);
            if (updated) {
                executeMain(onComplete);
            } else {
                PlayerSession online = sessions.get(targetLower);
                if (online != null) executeMain(() -> notifyDatabaseError(online.uuid));
            }
        });
    }

    /** Validating admin command variants; the old Runnable overload remains for binary callers. */
    public void adminRegister(String targetLower, String password, Consumer<String> reply) {
        if (!validPassword(password)) { reply.accept(auth.message("reg.usage")); return; }
        CompletableFuture.supplyAsync(() -> {
            DataSource.CheckResult available = ds().checkAuthAvailable(targetLower);
            if (!available.successful()) return "database.error";
            if (available.available()) return "reg.already";
            HashedPassword hp = sec().computeHash(password, targetLower);
            PlayerAuth pa = PlayerAuth.builder().name(targetLower).realName(targetLower)
                .password(hp.getHash(), hp.getSalt()).lastIp("")
                .registrationDate(System.currentTimeMillis()).registrationIp("")
                .locX(0).locY(0).locZ(0).locWorld("minecraft:overworld").build();
            return ds().saveAuth(pa) ? "admin.registered" : "database.error";
        }).thenAccept(key -> executeMain(() -> {
            if ("admin.registered".equals(key)) {
                PlayerSession online = sessions.get(targetLower);
                if (online != null) {
                    online.registered = true;
                    ServerPlayer p = onlinePlayer(online.uuid);
                    if (p != null) kick(p, auth.message("admin.registered", "player", targetLower));
                }
            }
            reply.accept(auth.message(key, "player", targetLower));
        })).exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    public void adminUnregister(String targetLower, Consumer<String> reply) {
        CompletableFuture.supplyAsync(() -> {
            DataSource.LookupResult lookup = ds().lookupAuth(targetLower);
            if (!lookup.successful()) return "database.error";
            if (lookup.auth() == null) return "admin.playerNotFound";
            return ds().removeAuth(targetLower) ? "admin.unregistered" : "database.error";
        }).thenAccept(key -> executeMain(() -> {
            if ("admin.unregistered".equals(key)) {
                PlayerSession online = sessions.remove(targetLower);
                if (online != null) {
                    online.authenticated = false;
                    ServerPlayer p = onlinePlayer(online.uuid);
                    if (p != null) kick(p, auth.message("unregister.success"));
                }
            }
            reply.accept(auth.message(key, "player", targetLower));
        })).exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    public void adminSetPassword(String targetLower, String password, Consumer<String> reply) {
        if (!validPassword(password)) { reply.accept(auth.message("reg.usage")); return; }
        CompletableFuture.supplyAsync(() -> {
            DataSource.LookupResult lookup = ds().lookupAuth(targetLower);
            if (!lookup.successful()) return "database.error";
            if (lookup.auth() == null) return "admin.playerNotFound";
            HashedPassword hp = sec().computeHash(password, targetLower);
            return ds().updatePassword(targetLower, hp) ? "admin.setpassword" : "database.error";
        }).thenAccept(key -> executeMain(() -> reply.accept(auth.message(key, "player", targetLower))))
            .exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    public void adminAuth(String targetLower, java.util.function.Consumer<String> reply) {
        CompletableFuture.supplyAsync(() -> {
            DataSource.LookupResult lookup = ds().lookupAuth(targetLower);
            if (!lookup.successful()) return "database.error";
            if (lookup.auth() == null) return "admin.playerNotFound";
            return ds().setLoginFlags(targetLower, true, false) ? "admin.authed" : "database.error";
        }).thenAccept(key -> executeMain(() -> {
            if ("admin.authed".equals(key)) {
                PlayerSession online = sessions.get(targetLower);
                if (online != null) {
                    online.authenticated = true;
                    online.pendingTotp = false;
                    ServerPlayer p = onlinePlayer(online.uuid);
                    if (p != null) {
                        p.setInvulnerable(false);
                        MinecraftText.send(p, auth.message("login.success"));
                    }
                }
            }
            reply.accept(auth.message(key, "player", targetLower));
        })).exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    public void adminUnauth(String targetLower, java.util.function.Consumer<String> reply) {
        CompletableFuture.supplyAsync(() -> {
            DataSource.LookupResult lookup = ds().lookupAuth(targetLower);
            if (!lookup.successful()) return "database.error";
            if (lookup.auth() == null) return "admin.playerNotFound";
            return ds().setLoginFlags(targetLower, false, false) ? "admin.unauthed" : "database.error";
        }).thenAccept(key -> executeMain(() -> {
            if ("admin.unauthed".equals(key)) {
                PlayerSession online = sessions.get(targetLower);
                if (online != null) {
                    online.authenticated = false;
                    online.pendingTotp = false;
                    ServerPlayer p = onlinePlayer(online.uuid);
                    if (p != null) {
                        p.setInvulnerable(true);
                        MinecraftText.send(p, auth.message("not_logged_in"));
                    }
                }
            }
            reply.accept(auth.message(key, "player", targetLower));
        })).exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    public void adminConverter(String id, String argument, java.util.function.BiConsumer<Integer, String> reply) {
        CompletableFuture.supplyAsync(() -> {
            Converter c = Converters.build(id, argument);
            if (c == null) return null;
            try {
                return c.convert(ds());
            } catch (Exception e) {
                Log.error("Converter '" + id + "' failed", e);
                Converter.Result r = new Converter.Result(0, 0, "Error: " + e.getMessage());
                return r;
            }
        }).thenAccept(r -> executeMain(() -> {
            if (r == null) {
                reply.accept(0, "&cUnknown converter: " + id + ". Run &e/authme converter list&c.");
            } else {
                String note = r.getNote().isEmpty() ? "" : " (" + r.getNote() + ")";

                reply.accept(r.getImported(), "&2Imported &a" + r.getImported() + "&2, skipped &a" + r.getSkipped() + note);
            }
        }));
    }

    public void accountData(String targetLower, Consumer<String> reply) {
        CompletableFuture
            .supplyAsync(() -> ds().lookupAuth(targetLower))
            .thenAccept(result -> executeMain(() -> {
                if (!result.successful()) {
                    reply.accept(auth.message("database.error"));
                    return;
                }
                PlayerAuth row = result.auth();
                if (row == null) {
                    reply.accept(auth.message("admin.playerNotFound", "player", targetLower));
                    return;
                }
                String date = row.getRegistrationDate() <= 0 ? "-"
                    : java.time.Instant.ofEpochMilli(row.getRegistrationDate()).toString();
                String last = row.getLastLogin() == null ? "-"
                    : java.time.Instant.ofEpochMilli(row.getLastLogin()).toString();
                reply.accept(auth.message("admin.accountdata", "player", targetLower,
                    "date", date, "ip", row.getLastIp() == null ? "-" : row.getLastIp(), "last", last));
            }))
            .exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    public void accounts(String targetLower, Consumer<String> reply) {
        CompletableFuture.supplyAsync(() -> ds().lookupAuth(targetLower)).thenAccept(result -> {
            if (!result.successful()) { executeMain(() -> reply.accept(auth.message("database.error"))); return; }
            if (result.auth() == null) { executeMain(() -> reply.accept(auth.message("admin.playerNotFound", "player", targetLower))); return; }
            DataSource.QueryResult<java.util.List<String>> accounts = ds().queryRegisteredNamesByIp(result.auth().getLastIp());
            executeMain(() -> reply.accept(accounts.successful()
                ? auth.message("admin.accounts", "player", targetLower, "ip", result.auth().getLastIp(), "accounts", String.join(", ", accounts.value()))
                : auth.message("database.error")));
        }).exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    public void adminGetIp(String targetLower, Consumer<String> reply) {
        CompletableFuture.supplyAsync(() -> ds().lookupAuth(targetLower)).thenAccept(result -> executeMain(() -> {
            if (!result.successful()) reply.accept(auth.message("database.error"));
            else if (result.auth() == null) reply.accept(auth.message("admin.playerNotFound", "player", targetLower));
            else reply.accept(auth.message("admin.ip", "player", targetLower, "ip", result.auth().getLastIp() == null ? "-" : result.auth().getLastIp()));
        }));
    }

    public void adminGetEmail(String targetLower, Consumer<String> reply) {
        CompletableFuture.supplyAsync(() -> ds().lookupAuth(targetLower)).thenAccept(result -> executeMain(() -> {
            if (!result.successful()) reply.accept(auth.message("database.error"));
            else if (result.auth() == null) reply.accept(auth.message("admin.playerNotFound", "player", targetLower));
            else reply.accept(auth.message("admin.email", "player", targetLower, "email", result.auth().getEmail() == null ? "-" : result.auth().getEmail()));
        }));
    }

    public void adminSetEmail(String targetLower, String email, Consumer<String> reply) {
        email = email == null ? "" : email.trim();
        if (!validEmailDomain(email)) { reply.accept(auth.message("email.invalid")); return; }
        final String normalizedEmail = email;
        CompletableFuture.supplyAsync(() -> {
            DataSource.LookupResult lookup = ds().lookupAuth(targetLower);
            if (!lookup.successful()) return "database.error";
            if (lookup.auth() == null) return "admin.playerNotFound";
            if (normalizedEmail.equalsIgnoreCase(lookup.auth().getEmail())) return "admin.emailSet";
            DataSource.CountResult count = ds().countRegisteredByEmail(normalizedEmail);
            if (!count.successful()) return "database.error";
            if (cfg().maxRegistrationsPerEmail() > 0 && count.count() >= cfg().maxRegistrationsPerEmail()) return "email.max";
            return ds().updateEmail(targetLower, normalizedEmail) ? "admin.emailSet" : "database.error";
        }).thenAccept(key -> executeMain(() -> reply.accept(auth.message(key))))
            .exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    public void adminTotpStatus(String targetLower, Consumer<String> reply) {
        CompletableFuture.supplyAsync(() -> ds().lookupAuth(targetLower)).thenAccept(result -> executeMain(() -> {
            if (!result.successful()) reply.accept(auth.message("database.error"));
            else if (result.auth() == null) reply.accept(auth.message("admin.playerNotFound", "player", targetLower));
            else reply.accept(auth.message("admin.totp", "player", targetLower, "status", result.auth().getTotpKey() == null || result.auth().getTotpKey().isBlank() ? "disabled" : "enabled"));
        }));
    }

    public void adminDisableTotp(String targetLower, Consumer<String> reply) {
        CompletableFuture.supplyAsync(() -> {
            DataSource.LookupResult lookup = ds().lookupAuth(targetLower);
            if (!lookup.successful()) return "database.error";
            if (lookup.auth() == null) return "admin.playerNotFound";
            return ds().updateTotpKey(targetLower, null) ? "admin.totpDisabled" : "database.error";
        }).thenAccept(key -> executeMain(() -> reply.accept(auth.message(key, "player", targetLower))))
            .exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    public void recent(int limit, Consumer<String> reply) {
        CompletableFuture.supplyAsync(() -> ds().queryRecentAccounts(limit)).thenAccept(result -> executeMain(() -> {
            if (!result.successful()) { reply.accept(auth.message("database.error")); return; }
            String names = result.value().stream().map(a -> a.getName() + "(" + a.getLastIp() + ")").collect(java.util.stream.Collectors.joining(", "));
            reply.accept(auth.message("admin.recent", "accounts", names));
        })).exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    public void purge(Consumer<String> reply) {
        purge(cfg().purgeDays(), reply);
    }

    public void purge(int days, Consumer<String> reply) {
        long cutoff = System.currentTimeMillis() - Math.max(1, days) * 86_400_000L;
        CompletableFuture.supplyAsync(() -> purgeOld(cutoff)).thenAccept(result -> executeMain(() -> reply.accept(result.operation().successful() ? auth.message("admin.purged", "count", result.operation().affected()) : auth.message("database.error"))));
    }

    private void runAutoPurge() {
        long cutoff = System.currentTimeMillis() - cfg().purgeDays() * 86_400_000L;
        CompletableFuture.supplyAsync(() -> purgeOld(cutoff))
            .thenAccept(result -> {
                if (result.operation().successful()) Log.info("Automatic AuthMe purge removed " + result.operation().affected() + " account(s) and " + result.files() + " related file(s).");
                else Log.error("Automatic AuthMe purge failed.");
                if (cfg().purgeBannedPlayers()) {
                    purgeBannedPlayers(message -> Log.info("Automatic banned-player purge completed: " + message));
                }
            })
            .exceptionally(error -> { Log.error("Automatic AuthMe purge failed", error); return null; });
    }

    public void purgePlayer(String targetLower, Consumer<String> reply) {
        purgePlayer(targetLower, false, reply);
    }

    public void purgePlayer(String targetLower, boolean force, Consumer<String> reply) {
        CompletableFuture.supplyAsync(() -> {
            DataSource.LookupResult lookup = ds().lookupAuth(targetLower);
            if (!lookup.successful()) return new PurgeResult(new DataSource.OperationResult(0, false), List.of(), 0);
            if (lookup.auth() == null) return new PurgeResult(new DataSource.OperationResult(0, true), List.of(), 0);
            if (!force) return new PurgeResult(new DataSource.OperationResult(-1, true), List.of(lookup.auth()), 0);
            boolean removed = ds().removeAuth(targetLower);
            int files = removed ? PurgeFileCleaner.clean(FabricLoader.getInstance().getGameDir(), cfg(), List.of(lookup.auth()), auth.server() != null && auth.server().usesAuthentication()) : 0;
            return new PurgeResult(new DataSource.OperationResult(removed ? 1 : 0, true), List.of(lookup.auth()), files);
        }).thenAccept(result -> executeMain(() -> {
            if (!result.operation().successful()) reply.accept(auth.message("database.error"));
            else if (result.operation().affected() < 0) reply.accept(auth.message("admin.purgePlayerConfirm", "player", targetLower));
            else if (result.operation().affected() > 0) reply.accept(auth.message("admin.purgedPlayer", "player", targetLower));
            else reply.accept(auth.message("admin.playerNotFound", "player", targetLower));
        })).exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    private PurgeResult purgeOld(long cutoff) {
        DataSource.QueryResult<List<PlayerAuth>> candidates = ds().queryPurgeCandidates(cutoff, 10000);
        if (!candidates.successful()) return new PurgeResult(new DataSource.OperationResult(0, false), List.of(), 0);
        DataSource.OperationResult operation = ds().purgeRegisteredBefore(cutoff, 10000);
        int files = operation.successful() ? PurgeFileCleaner.clean(FabricLoader.getInstance().getGameDir(), cfg(), candidates.value(), auth.server() != null && auth.server().usesAuthentication()) : 0;
        return new PurgeResult(operation, candidates.value(), files);
    }

    public void purgeBannedPlayers(Consumer<String> reply) {
        java.util.Set<String> banned = auth.server() == null ? java.util.Set.of()
            : BanListBridge.names(auth.server().getPlayerList());
        CompletableFuture.supplyAsync(() -> {
            int removed = 0;
            java.util.List<PlayerAuth> purged = new java.util.ArrayList<>();
            for (String name : banned) {
                DataSource.LookupResult lookup = ds().lookupAuth(name);
                if (lookup.successful() && lookup.auth() != null && ds().removeAuth(name)) { removed++; purged.add(lookup.auth()); }
            }
            PurgeFileCleaner.clean(FabricLoader.getInstance().getGameDir(), cfg(), purged, auth.server() != null && auth.server().usesAuthentication());
            return removed;
        }).thenAccept(count -> executeMain(() -> reply.accept(auth.message("admin.purgedBanned", "count", count))))
            .exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    public void resetPosition(String targetLower, Consumer<String> reply) {
        CompletableFuture.supplyAsync(() -> {
            DataSource.LookupResult lookup = ds().lookupAuth(targetLower);
            if (!lookup.successful()) return "database.error";
            if (lookup.auth() == null) return "admin.playerNotFound";
            return ds().updateLocation(targetLower, 0, 64, 0, 0, 0, "minecraft:overworld") ? "admin.resetpos" : "database.error";
        }).thenAccept(key -> executeMain(() -> reply.accept(auth.message(key, "player", targetLower))))
            .exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    public void resetAllPositions(Consumer<String> reply) {
        CompletableFuture.supplyAsync(() -> ds().resetAllLocations())
            .thenAccept(ok -> executeMain(() -> reply.accept(auth.message(ok ? "admin.resetposAll" : "database.error"))))
            .exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    public void debug(Consumer<String> reply) {
        DataSource source = ds();
        AntiBotManager antiBot = auth.antiBot();
        reply.accept("&7backend=" + (source == null ? "none" : source.getType()) + " healthy=" + auth.healthy() + " accounts=" + (source == null ? 0 : source.countAuths()) + " sessions=" + sessions.size() + " antibot=" + (antiBot != null && antiBot.isEnabled()));
    }

    /** Implements the portable subset of AuthMe's /authme debug child sections. */
    public void debug(String child, String arg1, String arg2, Consumer<String> reply) {
        String section = child == null ? "" : child.trim().toLowerCase(Locale.ROOT);
        if (section.isEmpty() || "stats".equals(section)) { debug(reply); return; }
        if ("db".equals(section) || "player".equals(section) || "auth".equals(section)) {
            if (arg1 == null || arg1.isBlank()) { reply.accept("&7Usage: /authme debug db <player>"); return; }
            accountData(arg1.toLowerCase(Locale.ROOT), reply); return;
        }
        if ("cty".equals(section) || "country".equals(section)) {
            if (arg1 == null || arg1.isBlank()) { reply.accept("&7Usage: /authme debug cty <ip>"); return; }
            var geo = auth.geoIp();
            if (geo == null) { reply.accept("&cGeoIP is not initialized."); return; }
            reply.accept("&7address=" + arg1 + " country=" + geo.countryCode(arg1) + " allowed=" + geo.isAllowed(arg1)); return;
        }
        if ("valid".equals(section)) {
            String type = arg1 == null ? "" : arg1.toLowerCase(Locale.ROOT);
            String value = arg2 == null ? "" : arg2;
            if ("password".equals(type)) reply.accept("&7passwordValid=" + validPassword(value));
            else if ("email".equals(type)) reply.accept("&7emailValid=" + validEmailDomain(value));
            else reply.accept("&7Usage: /authme debug valid <password|email> <value>");
            return;
        }
        if ("spawn".equals(section)) {
            reply.accept("&7spawn=" + spawnStore.get("spawn") + " firstSpawn=" + spawnStore.get("firstspawn")); return;
        }
        reply.accept("&cUnknown debug section '&f" + child + "&c'. Supported on Fabric: stats, db, cty, valid, spawn.");
    }

    public void setSpawn(ServerPlayer player, boolean first, Consumer<String> reply) {
        boolean saved = spawnStore.set(first ? "firstSpawn" : "spawn", new SpawnLocation(worldKey(player), player.getX(), player.getY(), player.getZ(), player.getYRot(), player.getXRot()));
        reply.accept(auth.message(saved ? "admin.spawnSet" : "database.error", "type", first ? "first" : "main"));
    }

    public void spawn(ServerPlayer player, boolean first, Consumer<String> reply) {
        reply.accept(teleportToConfiguredSpawn(player, first) ? auth.message("admin.spawnTeleported") : auth.message("admin.spawnMissing"));
    }

    private boolean teleportToConfiguredSpawn(ServerPlayer player, boolean first) {
        SpawnLocation location = spawnStore.get(first ? "firstSpawn" : "spawn");
        if (location == null) {
            net.minecraft.core.BlockPos pos = player.level().getRespawnData().pos();
            location = new SpawnLocation(worldKey(player), pos.getX() + 0.5, pos.getY(), pos.getZ() + 0.5, player.getYRot(), player.getXRot());
        }
        if (!location.world().equalsIgnoreCase(worldKey(player))) return false;
        player.teleportTo(player.level(), location.x(), location.y(), location.z(), java.util.Set.of(), location.yaw(), location.pitch(), false);
        player.setDeltaMovement(Vec3.ZERO);
        return true;
    }

    public void backup(Consumer<String> reply) {
        CompletableFuture.supplyAsync(() -> {
            try {
                Path directory = cfg().configDir().resolve("backups");
                Files.createDirectories(directory);
                Path file = directory.resolve("authme-" + java.time.format.DateTimeFormatter
                    .ofPattern("yyyyMMdd-HHmmss").withZone(java.time.ZoneOffset.UTC)
                    .format(java.time.Instant.now()) + ".sql");
                return ds().backup(file) ? file : null;
            } catch (Exception e) {
                Log.error("Could not create AuthMe backup", e);
                return null;
            }
        }).thenAccept(file -> executeMain(() -> reply.accept(file == null
            ? auth.message("database.error")
            : auth.message("admin.backup", "file", file.toString()))))
            .exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    // ===================================================================== queries used by events / mixin

    public boolean isUnauthenticated(ServerPlayer player) {
        if (!cfg().restrictUnauthenticated()) return false;
        PlayerSession s = sessions.get(realName(player).toLowerCase(Locale.ROOT));
        return s == null || (!s.authenticated && (s.registered || cfg().registrationForce()));
    }

    /** Authentication state used by message hooks even when movement/command protection is disabled. */
    public boolean isAuthenticated(ServerPlayer player) {
        if (player == null) return false;
        PlayerSession s = sessions.get(realName(player).toLowerCase(Locale.ROOT));
        return s != null && s.authenticated;
    }

    private void hideTabEntry(ServerPlayer subject) {
        MinecraftServer server = auth.server();
        if (server == null) return;
        ClientboundPlayerInfoRemovePacket subjectRemoval =
            new ClientboundPlayerInfoRemovePacket(List.of(subject.getUUID()));
        for (ServerPlayer viewer : server.getPlayerList().getPlayers()) {
            viewer.connection.send(subjectRemoval);
        }
        for (ServerPlayer viewer : server.getPlayerList().getPlayers()) {
            if (viewer != subject && isUnauthenticated(viewer)) {
                subject.connection.send(new ClientboundPlayerInfoRemovePacket(List.of(viewer.getUUID())));
            }
        }
    }

    private void showTabEntry(ServerPlayer subject) {
        MinecraftServer server = auth.server();
        if (server == null) return;
        ClientboundPlayerInfoUpdatePacket packet = new ClientboundPlayerInfoUpdatePacket(
            EnumSet.of(ClientboundPlayerInfoUpdatePacket.Action.ADD_PLAYER), List.of(subject));
        for (ServerPlayer viewer : server.getPlayerList().getPlayers()) {
            viewer.connection.send(packet);
        }
    }

    public boolean isCommandAllowed(ServerPlayer player, String rootToken) {
        if (rootToken == null) return true;
        String t = rootToken.toLowerCase(Locale.ROOT);
        for (String allowed : cfg().allowedCommands()) {
            if (t.equals(allowed.toLowerCase(Locale.ROOT))) return true;
        }

        return false;
    }

    // ===================================================================== tick

    public void tick() {
        MinecraftServer server = auth.server();
        if (server == null) return;
        tickCounter++;
        runScheduledCommands();
        if (!autoPurgeStarted) {
            autoPurgeStarted = true;
            if (cfg().purgeEnabled()) runAutoPurge();
        }
        long now = System.currentTimeMillis();
        if (cfg().backupEnabled() && cfg().backupIntervalHours() > 0) {
            long interval = cfg().backupIntervalHours() * 3_600_000L;
            if (lastAutoBackupMillis == 0L) lastAutoBackupMillis = now;
            else if (now - lastAutoBackupMillis >= interval) {
                lastAutoBackupMillis = now;
                backup(message -> Log.info("Automatic AuthMe backup completed: " + message));
            }
        }
        int chatRate = Math.max(1, cfg().registrationMessageIntervalSeconds()) * 20;
        int actionBarRate = 2 * 20;
        for (PlayerSession s : sessions.values()) {
            ServerPlayer p = onlinePlayer(s.uuid);
            if (p == null) continue;
            if (s.authenticated) continue;
            if (!s.accountResolved) continue;
            if (!s.registered && !cfg().registrationForce()) {
                p.setInvulnerable(false);
                continue;
            }
            // freeze
            if (!cfg().allowMovement()) {
                double dx = p.getX() - s.frozenX;
                double dy = p.getY() - s.frozenY;
                double dz = p.getZ() - s.frozenZ;
                double radius = Math.max(0.0, cfg().allowedMovementRadius());
                double horiz = dx * dx + dz * dz;
                if (horiz > radius * radius || Math.abs(dy) > 0.1) {
                    p.teleportTo(p.level(), s.frozenX, s.frozenY, s.frozenZ, java.util.Set.of(), p.getYRot(), p.getXRot(), false);
                    p.setDeltaMovement(Vec3.ZERO);
                }
            }
            if (cfg().removeSpeed()) p.setDeltaMovement(Vec3.ZERO);
            // prompt
            if (tickCounter % chatRate == 0) {
                schedulePrompt(p, s, s.registered);
            }
            if (tickCounter % (actionBarRate - 20) == 0) {
                MinecraftText.sendActionBar(p, "&eAuthMe &7» &a/login &7| &a/register");
            }
            // timeout
            int effective = s.registered ? cfg().loginTimeout() : cfg().registrationTimeout();
            if (effective > 0 && (now - s.joinTime) / 1000 > effective) {
                kick(p, auth.message("login.timeout"));
            }
        }
        if (tickCounter % 6000 == 0) {
            // periodic cache cleanup
            sessions.entrySet().removeIf(e -> onlinePlayer(e.getValue().uuid) == null);
        }
    }

    // ===================================================================== internals

    private void schedulePrompt(ServerPlayer player, PlayerSession session, boolean registered) {
        if (registered) {
            MinecraftText.send(player, auth.message("login.prompt"));
        } else {
            MinecraftText.send(player, auth.message("reg.prompt"));
        }
        if (session.captchaPending) {
            MinecraftText.send(player, auth.message("captcha.required", "code", session.captchaCode));
        }
        // keep session reference fresh
        session.lastIp = ip(player);
    }

    private void requireCaptcha(PlayerSession session) {
        session.captchaPending = true;
        session.captchaCode = RandomStringUtils.generateNum(Math.max(3, cfg().captchaLength()));
    }

    private record ScheduledCommand(long dueTick, ServerPlayer player, EventCommands.ConfiguredCommand command, String text) { }

    private void runEventCommands(String event, ServerPlayer player) {
        if (player == null) return;
        for (EventCommands.ConfiguredCommand command : eventCommands.get(event)) {
            if (command.accountsAtLeast() < 0 && command.accountsLessThan() < 0) { scheduleCommand(player, command); continue; }
            CompletableFuture.supplyAsync(() -> ds().queryRegisteredNamesByIp(ip(player))).thenAccept(result -> executeMain(() -> {
                if (!result.successful()) return;
                int count = result.value().size();
                if (command.accountsAtLeast() >= 0 && count < command.accountsAtLeast()) return;
                if (command.accountsLessThan() >= 0 && count >= command.accountsLessThan()) return;
                scheduleCommand(player, command);
            }));
        }
    }

    private void runAntiBotCommands(ServerPlayer player) {
        MinecraftServer server = auth.server();
        if (server == null) return;
        for (String configured : cfg().antiBotCommands()) {
            if (configured == null || configured.isBlank()) continue;
            String command = configured.trim();
            if (command.startsWith("/")) command = command.substring(1);
            command = command.replace("%p", realName(player)).replace("%nick", realName(player)).replace("%ip", ip(player));
            server.getCommands().performPrefixedCommand(server.createCommandSourceStack().withSuppressedOutput(), command);
        }
    }

    private void scheduleCommand(ServerPlayer player, EventCommands.ConfiguredCommand command) {
        String text = command.command().replace("%p", realName(player).toLowerCase(Locale.ROOT)).replace("%nick", realName(player)).replace("%ip", ip(player)).replace("%country", "");
        if (command.delayTicks() <= 0) executeEventCommand(player, command, text);
        else scheduledCommands.add(new ScheduledCommand(tickCounter + command.delayTicks(), player, command, text));
    }

    private void runScheduledCommands() {
        for (ScheduledCommand scheduled : scheduledCommands) {
            if (scheduled.dueTick() > tickCounter) continue;
            scheduledCommands.remove(scheduled);
            if (!offline(scheduled.player())) executeEventCommand(scheduled.player(), scheduled.command(), scheduled.text());
        }
    }

    private void executeEventCommand(ServerPlayer player, EventCommands.ConfiguredCommand command, String text) {
        MinecraftServer server = auth.server();
        if (server == null) return;
        String commandText = text.startsWith("/") ? text.substring(1) : text;
        try {
            if (command.executor() == EventCommands.Executor.PLAYER) server.getCommands().performPrefixedCommand(player.createCommandSourceStack(), commandText);
            else server.getCommands().performPrefixedCommand(server.createCommandSourceStack().withSuppressedOutput(), commandText);
        } catch (RuntimeException e) { Log.error("Configured AuthMe event command failed: " + commandText, e); }
    }

    private boolean validNickname(String name) {
        if (name == null || name.length() < cfg().minNicknameLength()
            || name.length() > cfg().maxNicknameLength()) return false;
        try { return name.matches(cfg().allowedNicknameCharacters()); }
        catch (RuntimeException e) { return name.matches("^[A-Za-z0-9_]+$"); }
    }

    private boolean validPassword(String password) {
        if (password == null || password.length() < cfg().minPasswordLength()
            || password.length() > cfg().maxPasswordLength()
            || cfg().unsafePasswords().contains(password.toLowerCase(Locale.ROOT))) return false;
        try { return password.matches(cfg().allowedPasswordCharacters()); }
        catch (RuntimeException e) { return false; }
    }

    private boolean validEmailDomain(String email) {
        if (email == null || !email.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")) return false;
        String domain = email.substring(email.lastIndexOf('@') + 1).toLowerCase(Locale.ROOT);
        for (String blocked : cfg().emailBlacklist()) if (!blocked.isBlank() && domain.equalsIgnoreCase(blocked.trim())) return false;
        List<String> whitelist = cfg().emailWhitelist();
        return whitelist.isEmpty() || whitelist.stream().anyMatch(allowed -> domain.equalsIgnoreCase(allowed.trim()));
    }

    private boolean hasReachedMaxJoinPerIp(String address) {
        int limit = cfg().maxJoinPerIp();
        if (limit <= 0 || isLoopbackAddress(address)) return false;
        int count = 0;
        for (PlayerSession session : sessions.values()) {
            if (session.active && sameAddress(address, session.lastIp)) count++;
        }
        return count >= limit;
    }

    private boolean hasReachedMaxLoginPerIp(String address, String currentName) {
        int limit = cfg().maxLoginPerIp();
        if (limit <= 0 || isLoopbackAddress(address)) return false;
        int count = 0;
        for (PlayerSession session : sessions.values()) {
            if (session.active && session.authenticated && !session.name.equals(currentName)
                && sameAddress(address, session.lastIp)) count++;
        }
        return count >= limit;
    }

    private static boolean sameAddress(String left, String right) {
        return normalizeIp(left).equalsIgnoreCase(normalizeIp(right));
    }

    private static boolean isLoopbackAddress(String address) {
        String normalized = normalizeIp(address);
        return normalized.startsWith("127.") || "::1".equals(normalized)
            || "0:0:0:0:0:0:0:1".equals(normalized) || "localhost".equals(normalized);
    }

    private void enforceSingleSession(String lower, PlayerSession current) {
        for (PlayerSession other : sessions.values()) {
            if (other == current || !other.authenticated || !other.name.equals(lower)) continue;
            other.authenticated = false;
            other.pendingTotp = false;
            ServerPlayer previous = onlinePlayer(other.uuid);
            if (previous != null) { previous.setInvulnerable(true); kick(previous, auth.message("login.singleSession")); }
            CompletableFuture.runAsync(() -> ds().setLoginFlags(lower, false, false));
        }
    }

    private void displayOtherAccounts(ServerPlayer player, String address) {
        CompletableFuture.supplyAsync(() -> ds().queryRegisteredNamesByIp(address)).thenAccept(result -> executeMain(() -> {
                if (!result.successful() || result.value().size() <= 1
                    || result.value().size() <= cfg().otherAccountsThreshold()) return;
            MinecraftText.send(player, auth.message("admin.otherAccounts", "accounts", String.join(", ", result.value())));
            String configured = cfg().otherAccountsCommand();
            if (!configured.isBlank() && auth.server() != null) {
                String command = configured.replace("%playername%", realName(player))
                    .replace("%playerip%", ip(player)).replace("%p", realName(player))
                    .replace("%nick", realName(player)).replace("%ip", ip(player));
                if (command.startsWith("/")) command = command.substring(1);
                auth.server().getCommands().performPrefixedCommand(
                    auth.server().createCommandSourceStack().withSuppressedOutput(), command);
            }
        }));
    }

    private synchronized int recordLoginFailure(String address) {
        String key = normalizeIp(address);
        long now = System.currentTimeMillis();
        LoginFailure failure = loginFailures.computeIfAbsent(key, ignored -> new LoginFailure());
        long resetMinutes = cfg().tempbanEnabled()
            ? cfg().tempbanCounterResetMinutes() : cfg().captchaResetMinutes();
        long window = Math.max(1L, resetMinutes) * 60_000L;
        if (failure.windowStarted == 0L || now - failure.windowStarted > window) {
            failure.windowStarted = now;
            failure.attempts = 0;
            failure.bannedUntil = 0L;
        }
        return ++failure.attempts;
    }

    private synchronized int failureAttempts(String address) {
        String key = normalizeIp(address);
        LoginFailure failure = loginFailures.get(key);
        if (failure == null) return 0;
        long resetMinutes = cfg().tempbanEnabled()
            ? cfg().tempbanCounterResetMinutes() : cfg().captchaResetMinutes();
        if (System.currentTimeMillis() - failure.windowStarted > Math.max(1L, resetMinutes) * 60_000L) {
            loginFailures.remove(key);
            return 0;
        }
        return failure.attempts;
    }

    private synchronized void banIp(String address) {
        LoginFailure failure = loginFailures.computeIfAbsent(normalizeIp(address), ignored -> new LoginFailure());
        failure.bannedUntil = System.currentTimeMillis() + Math.max(1L, cfg().tempbanLengthMinutes()) * 60_000L;
    }

    private void applyTempban(ServerPlayer player, String address) {
        String configured = cfg().tempbanCustomCommand();
        if (configured == null || configured.isBlank()) { banIp(address); return; }
        MinecraftServer server = auth.server();
        if (server == null) { banIp(address); return; }
        String command = configured.replace("%player%", realName(player)).replace("%p", realName(player))
            .replace("%nick", realName(player)).replace("%ip%", address == null ? "" : address)
            .replace("%ip", address == null ? "" : address);
        if (command.startsWith("/")) command = command.substring(1);
        try { server.getCommands().performPrefixedCommand(server.createCommandSourceStack().withSuppressedOutput(), command); }
        catch (RuntimeException e) { Log.error("Configured AuthMe tempban command failed; applying the internal safety ban", e); banIp(address); }
    }

    private synchronized boolean isTempBanned(String address) {
        if (!cfg().tempbanEnabled()) return false;
        String key = normalizeIp(address);
        LoginFailure failure = loginFailures.get(key);
        if (failure == null || failure.bannedUntil <= 0L) return false;
        if (failure.bannedUntil <= System.currentTimeMillis()) {
            loginFailures.remove(key);
            return false;
        }
        return true;
    }

    private synchronized void clearLoginFailures(String address) {
        loginFailures.remove(normalizeIp(address));
    }

    private static String normalizeIp(String address) {
        if (address == null) return "";
        String value = address.trim().toLowerCase(Locale.ROOT);
        if (value.startsWith("[") && value.contains("]")) value = value.substring(1, value.indexOf(']'));
        return value;
    }

    private boolean restrictedIpAllowed(String playerName, String address) {
        boolean restricted = false;
        String name = playerName.toLowerCase(Locale.ROOT);
        for (String entry : cfg().allowedRestrictedUsers()) {
            if (entry == null) continue;
            int separator = entry.indexOf(';');
            if (separator <= 0) continue;
            if (!name.equals(entry.substring(0, separator).trim().toLowerCase(Locale.ROOT))) continue;
            restricted = true;
            String rule = entry.substring(separator + 1).trim();
            if (rule.regionMatches(true, 0, "regex:", 0, 6)) {
                try {
                    if (java.util.regex.Pattern.matches(rule.substring(6), address)) return true;
                } catch (RuntimeException ignored) {
                    Log.warn("Invalid restricted-user IP regex for " + playerName);
                }
            } else {
                String regex = java.util.regex.Pattern.quote(rule).replace("*", "\\E.*\\Q");
                if (java.util.regex.Pattern.matches(regex, address)) return true;
            }
        }
        return !restricted;
    }

    private static String restrictedKey(String playerName, String address) {
        return playerName.toLowerCase(Locale.ROOT) + "\u0000" + normalizeIp(address);
    }

    private void completeLogin(ServerPlayer player, PlayerSession session, PlayerAuth authRow) {

        completeLogin(player, session, authRow, null);
    }

    private void completeLogin(ServerPlayer player, PlayerSession session, PlayerAuth authRow, Runnable onSuccess) {
        String lower = session.name;
        long generation = ++session.loginGeneration;
        CompletableFuture.supplyAsync(() -> {
            long now = System.currentTimeMillis();
            return ds().setLoginState(lower, session.lastIp, now, cfg().sessionEnabled());
        }).thenAccept(saved -> executeMain(() -> {
            boolean stillCurrent = session.active && session.loginGeneration == generation
                && sessions.get(lower) == session && !offline(player);
            if (!saved || !stillCurrent) {
                if (saved && !stillCurrent) CompletableFuture.runAsync(() -> ds().setLoginFlags(lower, false, false));
                if (!saved && !offline(player)) failDatabase(player, session);
                return;
            }
            session.authenticated = true;
            session.pendingTotp = false;
            JoinLeaveMessageBridge.onAuthenticated(player);
            applyConfiguredGameMode(player, true);
            clearLoginFailures(session.lastIp);
            if (cfg().hideTablist()) showTabEntry(player);
            if (cfg().forceSingleSession()) enforceSingleSession(lower, session);
            String targetWorld = authRow.getLocWorld();
            boolean forceSpawn = cfg().forceSpawnOnJoin()
                && (cfg().forceSpawnWorlds().isEmpty() || cfg().forceSpawnWorlds().stream()
                    .anyMatch(world -> world.equals(worldKey(player))));
            if (!cfg().noTeleport() && forceSpawn) {
                teleportToConfiguredSpawn(player, false);
            } else if (!cfg().noTeleport() && targetWorld != null && !targetWorld.isEmpty()
                && targetWorld.equalsIgnoreCase(worldKey(player))) {
                double x = authRow.getLocX();
                double y = authRow.getLocY();
                double z = authRow.getLocZ();
                float yaw = authRow.getLocYaw();
                float pitch = authRow.getLocPitch();
                if (y < 1.0) y = session.frozenY;
                final double fy = y;
                executeMain(() -> player.teleportTo(player.level(), x, fy, z, java.util.Set.of(), yaw, pitch, false));
            }
            player.setInvulnerable(false);
            setBlindEffect(player, false);
            MinecraftText.send(player, auth.message("login.success"));
            sendWelcomeMessage(player, session);
            runEventCommands("onLogin", player);
            auth.emitProxyMessage(ProxyProtocol.LOGIN, lower);
            auth.connectPlayerToConfiguredServer(player);
            if (authRow.getLastLogin() == null || authRow.getLastLogin() <= 0L) runEventCommands("onFirstLogin", player);
            if (cfg().displayOtherAccounts()) displayOtherAccounts(player, session.lastIp);
            if (onSuccess != null) onSuccess.run();
        })).exceptionally(error -> { executeMain(() -> failDatabase(player, session)); return null; });
    }

    private void kick(ServerPlayer player, String message) {
        try {
            player.connection.disconnect(MinecraftText.toComponent(message));
        } catch (Exception e) {
            Log.error("Failed to disconnect " + realName(player), e);
        }
    }

    private void setBlindEffect(ServerPlayer player, boolean enabled) {
        if (player == null) return;
        if (enabled) {
            if (!cfg().applyBlindEffect()) return;
            player.addEffect(new MobEffectInstance(MobEffects.BLINDNESS, Integer.MAX_VALUE, 0, false, false, false));
        }
        else player.removeEffect(MobEffects.BLINDNESS);
    }

    private void sendWelcomeMessage(ServerPlayer player, PlayerSession session) {
        if (!cfg().welcomeEnabled()) return;
        List<String> lines = WelcomeMessage.load(cfg());
        if (lines.isEmpty()) return;
        MinecraftServer server = auth.server();
        int online = server == null ? 1 : server.getPlayerList().getPlayers().size();
        int maxPlayers = server == null ? online : server.getPlayerList().getMaxPlayers();
        int loggedIn = (int) sessions.values().stream().filter(value -> value.authenticated).count();
        for (String line : lines) {
            String rendered = WelcomeMessage.render(line, realName(player), session.lastIp, online, maxPlayers,
                worldKey(player), cfg().serverName(), loggedIn, "");
            if (cfg().welcomeBroadcast() && server != null) {
                for (ServerPlayer target : server.getPlayerList().getPlayers()) MinecraftText.send(target, rendered);
            } else {
                MinecraftText.send(player, rendered);
            }
        }
    }

    private void failDatabase(ServerPlayer player, PlayerSession session) {
        if (session != null) {
            session.authenticated = false;
            session.pendingTotp = false;
        }
        if (!offline(player)) {
            MinecraftText.send(player, auth.message("database.error"));
            kick(player, auth.message("database.error"));
        }
    }

    private void notifyDatabaseError(UUID uuid) {
        ServerPlayer player = onlinePlayer(uuid);
        if (player != null) MinecraftText.send(player, auth.message("database.error"));
    }


    // ===================================================================== small helpers

    private <T> void executeMain(Runnable r) {
        MinecraftServer s = auth.server();
        if (s != null) s.execute(r);
        else r.run();
    }

    private boolean offline(ServerPlayer p) {
        return auth.server() == null || auth.server().getPlayerList().getPlayer(p.getUUID()) == null;
    }

    private ServerPlayer onlinePlayer(UUID uuid) {
        if (auth.server() == null) return null;
        return auth.server().getPlayerList().getPlayer(uuid);
    }

    private static String realName(ServerPlayer p) {
        return p.getName().getString();
    }

    private static String ip(ServerPlayer p) {
        String ip = p.getIpAddress();
        if (ip == null) return "";
        while (ip.startsWith("/")) ip = ip.substring(1);
        if (ip.startsWith("[")) {
            int end = ip.indexOf(']');
            if (end > 0) return normalizeIp(ip.substring(1, end));
        }
        int first = ip.indexOf(':');
        int last = ip.lastIndexOf(':');
        if (first > 0 && first == last) ip = ip.substring(0, last);
        return normalizeIp(ip);
    }

    private static String worldKey(ServerPlayer p) {
        try {
            return p.level().dimension().location().toString();
        } catch (Exception e) {
            return "minecraft:overworld";
        }
    }

    private boolean countryAllowed(ServerPlayer player, String address) {
        if (player != null && player.hasPermissions(2)) return true;
        if (player != null && cfg().permissionCheckEnabled()
            && Boolean.TRUE.equals(PermissionBridge.check(player.getUUID(), "authme.bypasscountrycheck"))) return true;
        return auth.geoIp() == null || auth.geoIp().isAllowed(address);
    }

    private void applyConfiguredGameMode(ServerPlayer player, boolean afterLogin) {
        if (!cfg().forceSurvivalMode() || afterLogin != cfg().forceSurvivalOnlyAfterLogin()
            || player == null || bypassForceSurvival(player)) return;
        if (player.gameMode() != GameType.SURVIVAL) {
            boolean creative = player.gameMode() == GameType.CREATIVE;
            player.setGameMode(GameType.SURVIVAL);
            if (creative && cfg().resetInventoryIfCreative()) player.getInventory().clearContent();
        }
    }

    private boolean bypassForceSurvival(ServerPlayer player) {
        if (player.hasPermissions(2)) return true;
        return cfg().permissionCheckEnabled()
            && Boolean.TRUE.equals(PermissionBridge.check(player.getUUID(), "authme.bypassforcesurvival"));
    }
}
