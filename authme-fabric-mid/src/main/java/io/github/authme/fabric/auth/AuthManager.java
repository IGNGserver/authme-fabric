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
import io.github.authme.fabric.auth.SessionSecurityPolicy;
import io.github.authme.fabric.auth.EmailAddressPolicy;
import io.github.authme.fabric.util.Log;
import io.github.authme.fabric.util.MinecraftText;
import io.github.authme.fabric.util.BanListBridge;
import io.github.authme.fabric.util.ProxyProtocol;
import io.github.authme.fabric.util.PurgeFileCleaner;
import io.github.authme.fabric.util.PermissionBridge;
import io.github.authme.fabric.network.JoinLeaveMessageBridge;
import io.github.authme.fabric.mail.EmailSender;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.core.BlockPos;
import net.minecraft.network.protocol.game.ClientboundPlayerInfoRemovePacket;
import net.minecraft.network.protocol.game.ClientboundPlayerInfoUpdatePacket;
import net.minecraft.world.MenuProvider;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.entity.projectile.ThrownEnderpearl;
import net.minecraft.world.item.ItemStack;
import net.minecraft.world.item.Items;
import net.minecraft.world.phys.Vec3;
import net.minecraft.world.level.GameType;
import net.minecraft.world.level.Level;
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
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Core authentication logic. Tracks per-player in-memory sessions and persists state to the
 * AuthMe-shaped database, so a shared database works across this fabric port and the original plugin.
 *
 * <p>DB reads are performed off the main thread; results are applied on the next main-thread tick
 * via {@link MinecraftServer#execute(Runnable)}.
 */
public final class AuthManager {

    private static final int MAX_LIMBO_ENDER_PEARLS = 64;
    private static final int MAX_UNSAFE_IP_BLOCKS = 8192;
    private static final int MAX_EMAIL_RECOVERY_ENTRIES = 8192;
    private static final int MAX_SCHEDULED_COMMANDS = 8192;

    private final AuthMe auth;
    private final java.util.Map<String, PlayerSession> sessions = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, EmailChallenge> emailChallenges = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, Long> emailRecoveryLastSent = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.Set<String> unsafeIpBlocks = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final SecureRandom secureRandom = new SecureRandom();
    private final SpawnStore spawnStore;
    private final EventCommands eventCommands;
    private final UnrestrictedInventoryRegistry unrestrictedInventoryRegistry = new UnrestrictedInventoryRegistry();
    private LimboStateStore limboStore;
    private final java.util.List<ScheduledCommand> scheduledCommands = new java.util.concurrent.CopyOnWriteArrayList<>();
    private final Map<UUID, List<LimboEnderPearl>> limboEnderPearls = new java.util.concurrent.ConcurrentHashMap<>();
    private long tickCounter;
    private boolean autoPurgeStarted;
    private long lastAutoBackupMillis;

    private record LimboEnderPearl(ThrownEnderpearl entity, ServerLevel level,
                                   double x, double y, double z, Vec3 velocity,
                                   float yaw, float pitch) {
    }

    private record RegistrationCheck(DataSource.CheckResult availability, DataSource.CountResult byIp,
                                     DataSource.CountResult byEmail) { }
    private record JoinLookup(DataSource.LookupResult auth,
                              DataSource.FailureStateResult accountFailure,
                              DataSource.FailureStateResult sourceFailure) { }
    private record PurgeResult(DataSource.OperationResult operation, List<PlayerAuth> candidates, int files) { }

    public AuthManager(AuthMe auth) {
        this.auth = auth;
        this.spawnStore = new SpawnStore(auth.config().configDir());
        this.eventCommands = new EventCommands(auth.config().configDir());
        this.limboStore = new LimboStateStore(auth.config().configDir(), auth.config().limboPersistence(),
            auth.config().limboDistributionSize());
    }

    /** Refreshes file-backed command configuration without discarding online sessions. */
    public void reloadConfiguration() {
        eventCommands.load();
        limboStore = new LimboStateStore(auth.config().configDir(), auth.config().limboPersistence(),
            auth.config().limboDistributionSize());
        scheduledCommands.clear();
        autoPurgeStarted = false;
        lastAutoBackupMillis = 0L;
        unrestrictedInventoryRegistry.clearAll();
        syncOnlineRestrictionState();
    }

    /** Applies a newly reloaded restriction policy to sessions that are already online. */
    private void syncOnlineRestrictionState() {
        MinecraftServer server = auth.server();
        if (server == null) return;
        boolean showTab = !cfg().restrictUnauthenticated() || !cfg().hideTablist();
        for (ServerPlayer player : server.getPlayerList().getPlayers()) {
            PlayerSession session = sessions.get(realName(player).toLowerCase(Locale.ROOT));
            if (session == null || session.authenticated) {
                if (showTab) showTabEntry(player);
                continue;
            }
            if (isUnauthenticated(player) && cfg().restrictUnauthenticated()) {
                if (!session.limboCaptured) enterLimbo(player, session);
                setBlindEffect(player, true);
                if (cfg().hideTablist()) hideTabEntry(player);
            } else {
                if (session.limboCaptured) restoreLimbo(player, session);
                setBlindEffect(player, false);
                if (showTab) showTabEntry(player);
            }
        }
    }

    private AuthMeConfig cfg() { return auth.config(); }
    private DataSource ds() { return auth.dataSource(); }
    private PasswordSecurity sec() { return auth.passwordSecurity(); }

    // ===================================================================== join / quit

    /**
     * Makes room for an AuthMe VIP after the vanilla capacity check allowed the join. The
     * capacity mixin only bypasses the full-server branch; all vanilla ban/whitelist checks have
     * already completed before this method runs. If every current player is VIP, the joining
     * player is rejected again so VIPs cannot grow the server without a replacement slot.
     */
    public void handleVipJoin(ServerPlayer player) {
        MinecraftServer server = auth.server();
        if (player == null || server == null || !hasVipPermission(player)) return;
        var playerList = server.getPlayerList();
        if (playerList.getPlayers().size() <= playerList.getMaxPlayers()) return;

        for (ServerPlayer online : playerList.getPlayers()) {
            if (online != player && !hasVipPermission(online)) {
                kick(online, auth.message("kick_for_vip"));
                Log.info("VIP player " + realName(player) + " joined a full server; removed "
                    + realName(online) + " to make room.");
                return;
            }
        }

        Log.info("VIP player " + realName(player) + " tried to join, but the server had no non-VIP slot.");
        kick(player, auth.message("kick_full_server"));
    }

    public void onJoin(ServerPlayer player) {
        if (!auth.healthy()) {
            kick(player, auth.message("database.error"));
            return;
        }
        JoinLeaveMessageBridge.prepareJoin(player);
        unrestrictedInventoryRegistry.clear(player.getUUID());
        String joinIp = ip(player);
        AntiBotManager ab = auth.antiBot();
        boolean antibotBlocking = ab != null && ab.shouldBlockNewJoins();
        if (ab != null && ab.consumeDeactivationNotice()) {
            notifyAntiBotAdmins("antibot.auto_disabled", "duration", cfg().antiBotDurationMinutes());
        }
        if (antibotBlocking && !hasAuthMePermission(player, "authme.bypassantibot")) {
            kick(player, auth.message("account_tempban"));
            return;
        }

        String name = realName(player);
        String lower = name.toLowerCase(Locale.ROOT);
        PlayerSession session = new PlayerSession(player.getUUID(), lower);
        session.lastIp = joinIp;
        session.joinTime = System.currentTimeMillis();
        session.frozenX = player.getX();
        session.frozenY = player.getY();
        session.frozenZ = player.getZ();
        session.frozenWorld = worldKey(player);
        PlayerSession existing = sessions.get(lower);
        if (existing != null && existing.active && !existing.uuid.equals(player.getUUID())) {
            kick(player, auth.message("login.singleSession"));
            return;
        }
        sessions.put(lower, session);
        if (cfg().restrictUnauthenticated()) {
            enterLimbo(player, session);
            player.setDeltaMovement(Vec3.ZERO);
            setBlindEffect(player, true);
        }

        // AuthMe's name unrestriction is intended for NPCs and other trusted server-side
        // identities. It bypasses AuthMe's authentication and player restriction checks, but
        // still remains behind the connection-level health, tempban, and AntiBot gates above.
        if (isUnrestrictedName(lower)) {
            session.accountResolved = true;
            session.registered = true;
            session.authenticated = true;
            session.unrestrictedName = true;
            restoreLimbo(player, session);
            applyConfiguredGameMode(player, true);
            setBlindEffect(player, false);
            runEventCommands("onJoin", player);
            runEventCommands("onLogin", player);
            JoinLeaveMessageBridge.onAuthenticated(player);
            return;
        }

        applyConfiguredGameMode(player, false);
        if (cfg().protectionEnabled() && cfg().protectionRegistered() && !countryAllowed(player, joinIp)) {
            kick(player, auth.message("country_banned"));
            return;
        }
        if (cfg().allowRestrictedUsers()) {
            String restrictedKey = restrictedKey(name, joinIp);
            if (cfg().banUnsafeIp() && unsafeIpBlocks.contains(restrictedKey)) {
                kick(player, auth.message("restricted_user"));
                return;
            }
            if (!restrictedIpAllowed(name, joinIp)) {
                // Scope the temporary block to the restricted username as well as the address;
                // one failed attempt must not deny every player behind a shared/NAT address.
                if (cfg().banUnsafeIp()) rememberUnsafeIpBlock(restrictedKey);
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
        if (cfg().restrictUnauthenticated() && cfg().hideTablist()) hideTabEntry(player);

        if (ab != null && ab.notifyJoin(session.lastIp)) {
            runAntiBotCommands(player);
            notifyAntiBotAdmins("antibot.auto_enabled");
        }

        CompletableFuture
            .supplyAsync(() -> new JoinLookup(ds().lookupAuth(lower),
                ds().readFailureState(accountFailureStateKey(lower, joinIp),
                    System.currentTimeMillis(), failureWindowMillis()),
                ds().readFailureState(sourceFailureStateKey(joinIp),
                    System.currentTimeMillis(), failureWindowMillis())))
            .thenAccept(result -> executeMain(() -> {
                if (!result.auth().successful() || !result.accountFailure().successful()
                    || !result.sourceFailure().successful()) {
                    failDatabase(player, session);
                    return;
                }
                if (cfg().tempbanEnabled() && (result.accountFailure().bannedUntil() > System.currentTimeMillis()
                    || result.sourceFailure().bannedUntil() > System.currentTimeMillis())) {
                    kick(player, auth.message("account_tempban"));
                    return;
                }
                applyJoin(player, lower, session, result.auth().auth(), result.accountFailure().attempts());
            }))
            .exceptionally(error -> { executeMain(() -> failDatabase(player, session)); return null; });
    }

    private void applyJoin(ServerPlayer player, String lower, PlayerSession session, PlayerAuth authRow,
                           int sharedFailureAttempts) {
        if (!current(player, session)) return;
        session.accountResolved = true;
        session.registered = (authRow != null);
        applyPermissionGroup(player, session);
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
                restoreLimbo(player, session);
                setBlindEffect(player, false);
                if (cfg().captchaEnabled() && cfg().captchaForRegistration()) requireCaptcha(session);
                schedulePrompt(player, session, false);
                return;
            }
            if (cfg().captchaEnabled() && cfg().captchaForRegistration()) requireCaptcha(session);
            schedulePrompt(player, session, false);
            return;
        }
        session.lastLogin = authRow.getLastLogin() == null ? 0L : authRow.getLastLogin();

        if (cfg().captchaEnabled() && sharedFailureAttempts >= cfg().maxLoginTriesForCaptcha()) {
            requireCaptcha(session);
        }

        boolean autoLogin = false;
        boolean hasTotp = authRow.getTotpKey() != null && !authRow.getTotpKey().isBlank();
        if (!hasTotp && cfg().enablePremium() && auth.server() != null && auth.server().usesAuthentication()
            && authRow.getPremiumUuid() != null
            && authRow.getPremiumUuid().equals(player.getUUID())) {
            autoLogin = true;
        } else if (!hasTotp && cfg().sessionEnabled() && authRow.hasSession()) {
            long now = System.currentTimeMillis();
            long timeout = cfg().sessionTimeoutMinutes() * 60_000L;
            // A persisted session is a password bypass. It must always be
            // bound to the IP that created it; legacy switches cannot turn
            // this check off.
            if (SessionSecurityPolicy.canResume(authRow.getLastIp(), session.lastIp,
                session.lastLogin, now, timeout)) autoLogin = true;
        }

        if (autoLogin) {
            completeLogin(player, session, authRow,
                () -> { runEventCommands("onSessionLogin", player); MinecraftText.send(player, auth.message("login.success_session")); });
        } else {
            schedulePrompt(player, session, true);
        }
    }

    /** Records a thrown ender pearl while the owner is inside the unauthenticated limbo. */
    public void trackLimboEnderPearl(Entity entity, ServerLevel level) {
        if (!(entity instanceof ThrownEnderpearl pearl) || level == null) return;
        if (!(pearl.getOwner() instanceof ServerPlayer player) || !isUnauthenticated(player)) return;
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.active || !session.limboCaptured) return;
        List<LimboEnderPearl> tracked = limboEnderPearls.computeIfAbsent(session.uuid,
            ignored -> new CopyOnWriteArrayList<>());
        if (tracked.size() >= MAX_LIMBO_ENDER_PEARLS) return;
        for (LimboEnderPearl existing : tracked) {
            if (existing.entity() == pearl) return;
        }
        tracked.add(new LimboEnderPearl(pearl, level, pearl.getX(), pearl.getY(), pearl.getZ(),
            pearl.getDeltaMovement(), pearl.getYRot(), pearl.getXRot()));
    }

    public void onDisconnect(ServerPlayer player) {
        JoinLeaveMessageBridge.clear(player);
        if (player != null) unrestrictedInventoryRegistry.clear(player.getUUID());
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session != null) sessions.remove(lower, session);
        emailChallenges.remove("verify:" + lower);
        emailChallenges.remove("recover:" + lower);
        if (session == null) return;
        long expectedLastLogin = session.lastLogin;
        session.active = false;
        session.authenticationBusy = false;
        session.loginGeneration++;
        restoreLimbo(player, session);
        if (!session.authenticated || session.unrestrictedName) return;
        double x = player.getX(), y = player.getY(), z = player.getZ();
            float yaw = player.getYRot(), pitch = player.getXRot();
            String world = worldKey(player);
            runEventCommands("onLogout", player);
            auth.emitProxyMessage(ProxyProtocol.LOGOUT, lower);
            CompletableFuture.runAsync(() -> {
                boolean ok = ds().persistDisconnectIfLastLogin(lower, expectedLastLogin,
                    System.currentTimeMillis(), x, y, z, yaw, pitch, world,
                    cfg().saveQuitLocation(), cfg().sessionEnabled());
                if (!ok) Log.error("Failed to persist disconnect state for " + lower);
        }).whenComplete((r, e) -> { if (e != null) Log.error("Failed to flush session for " + lower, e); });
    }

    // ===================================================================== register / login

    public void login(ServerPlayer player, String password) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || session.authenticated) {
            MinecraftText.send(player, auth.message("login.already"));
            return;
        }
        if (password == null || password.length() > cfg().maxPasswordLength()) {
            onWrongPassword(player, session, lower);
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
        if (!beginAuthentication(player, session)) return;
        CompletableFuture
            .supplyAsync(() -> ds().lookupAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (!current(player, session)) return;
                if (!a.successful()) {
                    failDatabase(player, session);
                    return;
                }
                if (a.auth() == null) {
                    clearAuthentication(session);
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
                    HashedPassword rehashed = sec().computeHash(password, lower);
                    CompletableFuture.supplyAsync(() -> ds().updatePasswordIfMatches(lower, stored, rehashed))
                        .thenAccept(updated -> executeMain(() -> {
                            if (!current(player, session)) return;
                            if (!updated) {
                                clearAuthentication(session);
                                Log.warn("Rejected legacy login for " + lower
                                    + " because the password row changed during migration");
                                MinecraftText.send(player, auth.message("database.error"));
                                return;
                            }
                            Log.info("Rehashed legacy password for " + lower);
                            finishPasswordLogin(player, session, row);
                        }))
                        .exceptionally(error -> {
                            executeMain(() -> failDatabase(player, session));
                            return null;
                        });
                    return;
                }
                finishPasswordLogin(player, session, row);
            }))
            .exceptionally(error -> { executeMain(() -> failDatabase(player, session)); return null; });
    }

    /** Continues only after a legacy password compare-and-set has committed successfully. */
    private void finishPasswordLogin(ServerPlayer player, PlayerSession session, PlayerAuth row) {
        if (!current(player, session)) return;
        session.loginAttempts = 0;
        session.totpKey = row.getTotpKey();
        if (row.getTotpKey() != null && !row.getTotpKey().isEmpty()) {
            clearAuthentication(session);
            session.pendingTotp = true;
            session.proxyTotpPending = false;
            session.captchaPending = false;
            MinecraftText.send(player, auth.message("totp.required"));
        } else {
            completeLogin(player, session, row, null);
        }
    }

    /** Completes a login requested by a HMAC-authenticated AuthMe proxy. */
    public void forceLoginFromProxy(ServerPlayer player, String requestedName, UUID verifiedPremiumUuid) {
        if (!cfg().bungeecordHook() || player == null || requestedName == null
            || !realName(player).equalsIgnoreCase(requestedName)) {
            Log.warn("Rejected proxy login because the signed player name did not match the carrier connection.");
            return;
        }
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || session.authenticated || session.pendingTotp) return;
        if (!beginAuthentication(player, session)) return;
        CompletableFuture.supplyAsync(() -> ds().lookupAuth(lower))
            .thenAccept(result -> executeMain(() -> {
                if (!current(player, session)) return;
                if (!result.successful()) { failDatabase(player, session); return; }
                PlayerAuth row = result.auth();
                if (row == null) {
                    clearAuthentication(session);
                    Log.warn("Rejected proxy login for unregistered account " + lower);
                    return;
                }
                if (verifiedPremiumUuid != null && !verifiedPremiumUuid.equals(row.getPremiumUuid())) {
                    clearAuthentication(session);
                    Log.warn("Rejected proxy premium login for " + lower + ": UUID does not match the stored account");
                    return;
                }
                session.totpKey = row.getTotpKey();
                if (row.getTotpKey() != null && !row.getTotpKey().isBlank()) {
                    clearAuthentication(session);
                    session.pendingTotp = true;
                    session.proxyTotpPending = true;
                    session.captchaPending = false;
                    MinecraftText.send(player, auth.message("totp.required"));
                    return;
                }
                completeLogin(player, session, row, () -> auth.emitProxyMessage(ProxyProtocol.PERFORM_LOGIN_ACK, lower));
            }))
            .exceptionally(error -> { executeMain(() -> failDatabase(player, session)); return null; });
    }

    private void onWrongPassword(ServerPlayer player, PlayerSession session, String lower) {
        clearAuthentication(session);
        MinecraftText.send(player, auth.message("login.wrong"));
        CompletableFuture.supplyAsync(() -> recordLoginFailure(lower, session.lastIp)).thenAccept(attempts ->
            executeMain(() -> applyLoginFailure(player, session, lower, attempts)));
    }

    private void applyLoginFailure(ServerPlayer player, PlayerSession session, String lower, int attempts) {
        if (!current(player, session)) return;
        session.loginAttempts = attempts;
        LoginFailurePolicy.Action action = LoginFailurePolicy.decide(cfg().tempbanEnabled(), attempts,
            cfg().tempbanMaxLoginTries(), cfg().captchaEnabled(), cfg().maxLoginTriesForCaptcha(),
            cfg().kickOnWrongPassword());
        if (action == LoginFailurePolicy.Action.TEMPBAN) {
            applyTempban(player, session.lastIp);
            kick(player, auth.message("account_tempban"));
            Log.info("Temporarily blocked repeated login failures for " + lower + ".");
        } else if (action == LoginFailurePolicy.Action.CAPTCHA) {
            session.captchaPending = true;
            session.captchaCode = RandomStringUtils.generateNum(Math.max(3, cfg().captchaLength()));
            MinecraftText.send(player, auth.message("captcha.required", "code", session.captchaCode));
        } else if (action == LoginFailurePolicy.Action.KICK_WRONG_PASSWORD) {
            kick(player, auth.message("login.wrong"));
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
        if (!beginAuthentication(player, session)) return;
        final String registrationEmail = email;
        CompletableFuture
            .supplyAsync(() -> new RegistrationCheck(ds().checkAuthAvailable(lower),
                ds().countRegisteredByIp(session.lastIp),
                registrationEmail == null ? new DataSource.CountResult(0, true) : ds().countRegisteredByEmail(registrationEmail)))
            .thenAccept(check -> executeMain(() -> {
                if (!current(player, session)) return;
                if (!check.availability().successful() || !check.byIp().successful() || !check.byEmail().successful()) {
                    failDatabase(player, session);
                    return;
                }
                if (check.availability().available()) {
                    clearAuthentication(session);
                    MinecraftText.send(player, auth.message("reg.already"));
                    return;
                }
                if (cfg().maxRegistrationsPerIp() > 0
                    && !hasAuthMePermission(player, "authme.allowmultipleaccounts")
                    && check.byIp().count() >= cfg().maxRegistrationsPerIp()) {
                    clearAuthentication(session);
                    MinecraftText.send(player, auth.message("reg.maxIp"));
                    return;
                }
                if (registrationEmail != null && cfg().maxRegistrationsPerEmail() > 0
                    && check.byEmail().count() >= cfg().maxRegistrationsPerEmail()) {
                    clearAuthentication(session);
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
                            failDatabase(player, session);
                            return;
                        }
                        finishRegister(player, lower, session, pa);
                    }))
                    .exceptionally(error -> {
                        executeMain(() -> { clearAuthentication(session); MinecraftText.send(player, auth.message("database.error")); });
                        return null;
                    });
            }))
            .exceptionally(error -> {
                executeMain(() -> { clearAuthentication(session); MinecraftText.send(player, auth.message("database.error")); });
                return null;
            });
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
        if (!beginAuthentication(player, session)) return;
        final String registrationEmail = email;
        CompletableFuture
            .supplyAsync(() -> new RegistrationCheck(ds().checkAuthAvailable(lower),
                ds().countRegisteredByIp(session.lastIp), ds().countRegisteredByEmail(registrationEmail)))
            .thenAccept(check -> executeMain(() -> {
                if (!current(player, session)) return;
                if (!check.availability().successful() || !check.byIp().successful() || !check.byEmail().successful()) {
                    failDatabase(player, session);
                    return;
                }
                if (check.availability().available()) {
                    clearAuthentication(session);
                    MinecraftText.send(player, auth.message("reg.already"));
                    return;
                }
                if (cfg().maxRegistrationsPerIp() > 0
                    && !hasAuthMePermission(player, "authme.allowmultipleaccounts")
                    && check.byIp().count() >= cfg().maxRegistrationsPerIp()) {
                    clearAuthentication(session);
                    MinecraftText.send(player, auth.message("reg.maxIp"));
                    return;
                }
                if (cfg().maxRegistrationsPerEmail() > 0
                    && check.byEmail().count() >= cfg().maxRegistrationsPerEmail()) {
                    clearAuthentication(session);
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
                            failDatabase(player, session);
                            return;
                        }
                        session.registered = true;
                        clearAuthentication(session);
                        CompletableFuture.supplyAsync(() -> EmailSender.send(cfg(), registrationEmail,
                                "Your new AuthMe password",
                                "Your AuthMe account for " + realName(player) + " was created.\n"
                                    + "Your generated password is: " + generatedPassword))
                            .thenAccept(sent -> executeMain(() -> {
                                if (!current(player, session)) return;
                                MinecraftText.send(player, auth.message(sent ? "reg.emailSuccess" : "reg.emailSendFailure",
                                    "email", registrationEmail));
                                if (sent) runEventCommands("onRegister", player);
                            }));
                    }))
                    .exceptionally(error -> {
                        executeMain(() -> { clearAuthentication(session); MinecraftText.send(player, auth.message("database.error")); });
                        return null;
                    });
            }))
            .exceptionally(error -> {
                executeMain(() -> { clearAuthentication(session); MinecraftText.send(player, auth.message("database.error")); });
                return null;
            });
    }

    private void finishRegister(ServerPlayer player, String lower, PlayerSession session, PlayerAuth pa) {
        executeMain(() -> {
            if (!current(player, session)) return;
            MinecraftText.send(player, auth.message("reg.success", "?", ""));
            runEventCommands("onRegister", player);
            if (cfg().forceKickAfterRegister()) {
                session.registered = true;
                clearAuthentication(session);
                Runnable kickAction = () -> {
                    if (current(player, session)) kick(player, auth.message("reg.success"));
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
                clearAuthentication(session);
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
                if (!current(player, session)) return;
                if (!a.successful()) { failDatabase(player, session); return; }
                if (a.auth() == null) { MinecraftText.send(player, auth.message("unknown_user", "player", realName(player))); return; }
                PasswordSecurity.VerificationResult r = sec().verify(oldPw, a.auth().toHashedPassword(), lower);
                if (r == null) { MinecraftText.send(player, auth.message("changepassword.wrong")); return; }
                HashedPassword newHash = sec().computeHash(newPw, lower);
                CompletableFuture.supplyAsync(() -> ds().updatePassword(lower, newHash))
                    .thenAccept(updated -> executeMain(() -> {
                        if (!current(player, session)) return;
                        MinecraftText.send(player, auth.message(updated ? "changepassword.success" : "database.error"));
                    }))
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
                if (!current(player, session)) return;
                if (!updated) {
                    MinecraftText.send(player, auth.message("database.error"));
                    return;
                }
                session.authenticated = false;
                session.pendingTotp = false;
                runEventCommands("onLogout", player);
                auth.emitProxyMessage(ProxyProtocol.LOGOUT, lower);
                session.frozenX = player.getX();
                session.frozenY = player.getY();
                session.frozenZ = player.getZ();
                session.frozenWorld = worldKey(player);
                session.joinTime = System.currentTimeMillis();
                enterLimbo(player, session);
                applyPermissionGroup(player, session);
                MinecraftText.send(player, auth.message("logout.success"));
            }))
            .exceptionally(error -> { executeMain(() -> MinecraftText.send(player, auth.message("database.error"))); return null; });
    }

    public void unregister(ServerPlayer player, String password) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) return;
        CompletableFuture
            .supplyAsync(() -> ds().lookupAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (!current(player, session)) return;
                if (!a.successful()) { failDatabase(player, session); return; }
                if (a.auth() == null) { MinecraftText.send(player, auth.message("unknown_user", "player", realName(player))); return; }
                PasswordSecurity.VerificationResult r = sec().verify(password, a.auth().toHashedPassword(), lower);
                if (r == null) { MinecraftText.send(player, auth.message("unregister.wrong")); return; }
                CompletableFuture.supplyAsync(() -> ds().removeAuth(lower))
                    .thenAccept(removed -> executeMain(() -> {
                        if (!current(player, session)) return;
                        if (!removed) { MinecraftText.send(player, auth.message("database.error")); return; }
                        sessions.remove(lower, session);
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
            clearLoginFailures(lower, session.lastIp);
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
        long now = System.currentTimeMillis();
        if (session.totpBlockedUntil > now) {
            MinecraftText.send(player, auth.message("totp.wrong"));
            return;
        }
        if (!beginAuthentication(player, session)) return;
        CompletableFuture
            .supplyAsync(() -> ds().lookupAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (!current(player, session)) return;
                if (!a.successful()) { failDatabase(player, session); return; }
                PlayerAuth row = a.auth();
                String currentTotpKey = row == null ? null : row.getTotpKey();
                if (row == null || !TotpProvider.isPlausibleSecret(currentTotpKey)
                    || !TotpProvider.validateCode(currentTotpKey, code)) {
                    clearAuthentication(session);
                    recordTotpFailure(session);
                    CompletableFuture.runAsync(() -> recordLoginFailure(lower, session.lastIp));
                    MinecraftText.send(player, auth.message("totp.wrong"));
                    return;
                }
                clearTotpFailures(session);
                boolean proxyLogin = session.proxyTotpPending;
                session.proxyTotpPending = false;
                session.totpKey = currentTotpKey;
                completeLogin(player, session, row, () -> {
                    if (proxyLogin) auth.emitProxyMessage(ProxyProtocol.PERFORM_LOGIN_ACK, lower);
                    else MinecraftText.send(player, auth.message("totp.success"));
                });
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
                if (!current(player, session)) return;
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
                if (!current(player, session)) return;
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
                if (!current(player, session)) return;
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
                    .thenAccept(updated -> executeMain(() -> {
                        if (!current(player, session)) return;
                        MinecraftText.send(player, auth.message(updated ? "totp.disabled" : "database.error"));
                    }))
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
                        if (!current(player, session)) return;
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
                if (!current(player, session)) return;
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
                System.currentTimeMillis() + cfg().emailVerificationTimeoutSeconds() * 1000L, false);
            emailChallenges.put("verify:" + lower, challenge);
            CompletableFuture.supplyAsync(() -> EmailSender.send(cfg(), email, "AuthMe e-mail verification",
                    "Your AuthMe verification code is: " + code + "\nIt expires in "
                        + (cfg().emailVerificationTimeoutSeconds() / 60) + " minutes."))
                .thenAccept(sent -> executeMain(() -> {
                    if (!current(player, session)) return;
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
            .thenAccept(key -> executeMain(() -> {
                if (!current(player, session)) return;
                MinecraftText.send(player, auth.message(key));
            }))
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
            if (!current(player, session)) return;
            if (!"ok".equals(result)) { MinecraftText.send(player, auth.message(result)); return; }
            if (cfg().emailRequireVerification()) {
                if (!cfg().emailEnabled()) { MinecraftText.send(player, auth.message("email.recoveryDisabled")); return; }
                String code = recoveryCode();
                emailChallenges.put("verify:" + lower, new EmailChallenge(newValue, code, System.currentTimeMillis() + cfg().emailVerificationTimeoutSeconds() * 1000L, false));
                CompletableFuture.supplyAsync(() -> EmailSender.send(cfg(), newValue, "AuthMe e-mail verification", "Your AuthMe verification code is: " + code))
                    .thenAccept(sent -> executeMain(() -> {
                        if (!current(player, session)) return;
                        MinecraftText.send(player, auth.message(sent ? "email.verifySent" : "database.error"));
                    }));
            } else CompletableFuture.supplyAsync(() -> ds().updateEmail(lower, newValue))
                .thenAccept(updated -> executeMain(() -> {
                    if (!current(player, session)) return;
                    MinecraftText.send(player, auth.message(updated ? "email.changed" : "database.error"));
                }));
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
        PlayerSession session = sessions.get(lower);
        if (session == null) {
            MinecraftText.send(player, auth.message("email.recoverySent"));
            return;
        }
        if (!beginEmailRecovery(lower, ip(player))) {
            // Keep the response indistinguishable from a normal recovery
            // request so the cooldown cannot be used for account discovery.
            MinecraftText.send(player, auth.message("email.recoverySent"));
            return;
        }
        CompletableFuture.supplyAsync(() -> ds().getAuthByEmail(email.trim()))
            .thenAccept(account -> executeMain(() -> {
                if (!current(player, session)) return;
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
                        if (!current(player, session)) return;
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

    private boolean beginEmailRecovery(String playerName, String address) {
        String key = playerName + "\u0000" + normalizeIp(address);
        long now = System.currentTimeMillis();
        long cooldown = Math.max(1L, cfg().emailRecoveryCooldownSeconds()) * 1000L;
        synchronized (emailRecoveryLastSent) {
            emailRecoveryLastSent.entrySet().removeIf(entry -> now - entry.getValue() >= cooldown);
            Long previous = emailRecoveryLastSent.get(key);
            if (previous != null && now - previous < cooldown) return false;
            if (emailRecoveryLastSent.size() >= MAX_EMAIL_RECOVERY_ENTRIES) {
                java.util.Iterator<String> iterator = emailRecoveryLastSent.keySet().iterator();
                if (iterator.hasNext()) emailRecoveryLastSent.remove(iterator.next());
            }
            emailRecoveryLastSent.put(key, now);
            return true;
        }
    }

    public void emailConfirm(ServerPlayer player, String code) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        EmailChallenge recovery = emailChallenges.get("recover:" + lower);
        EmailChallenge verification = emailChallenges.get("verify:" + lower);
        EmailChallenge challenge = recovery != null ? recovery : verification;
        boolean valid = challenge != null && challenge.expiresAt >= System.currentTimeMillis()
            && constantTimeEquals(challenge.code, code);
        if (!valid) {
            if (challenge != null && ++challenge.failedAttempts >= cfg().emailRecoveryMaxAttempts()) {
                emailChallenges.remove(challenge.recovery ? "recover:" + lower : "verify:" + lower, challenge);
            }
            MinecraftText.send(player, auth.message(recovery != null ? "email.recoveryCodeWrong" : "email.verifyWrong"));
            return;
        }
        if (!current(player, session)) return;
        if (challenge.recovery) {
            challenge.verified = true;
            challenge.verifiedAt = System.currentTimeMillis();
            MinecraftText.send(player, auth.message("email.recoveryCode"));
        } else {
            CompletableFuture.supplyAsync(() -> {
                DataSource.CountResult count = ds().countRegisteredByEmail(challenge.email);
                if (!count.successful()) return "database.error";
                if (cfg().maxRegistrationsPerEmail() > 0 && count.count() >= cfg().maxRegistrationsPerEmail()) return "email.max";
                return ds().updateEmail(lower, challenge.email) ? "email.verified" : "database.error";
            }).thenAccept(key -> executeMain(() -> {
                    if (!current(player, session)) return;
                    if (!"email.verified".equals(key)) { MinecraftText.send(player, auth.message(key)); return; }
                    challenge.verified = true;
                    challenge.verifiedAt = System.currentTimeMillis();
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
        long passwordDeadline = challenge == null ? 0L
            : challenge.verifiedAt > 0L
                ? challenge.verifiedAt + cfg().emailPasswordChangeTimeoutSeconds() * 1000L
                : challenge.expiresAt;
        if (challenge == null || !challenge.recovery || !challenge.verified
            || passwordDeadline < System.currentTimeMillis()) {
            MinecraftText.send(player, auth.message("email.recoveryCodeWrong"));
            return;
        }
        if (!validPassword(password)) {
            MinecraftText.send(player, auth.message("reg.usage"));
            return;
        }
        if (session == null || !beginAuthentication(player, session)) return;
        HashedPassword hash = sec().computeHash(password, lower);
        CompletableFuture.supplyAsync(() -> ds().updatePasswordAndClearLogin(lower, hash)
                ? ds().lookupAuth(lower) : null)
            .thenAccept(result -> executeMain(() -> {
                if (!current(player, session)) return;
                if (result == null || !result.successful() || result.auth() == null || session == null) {
                    clearAuthentication(session);
                    MinecraftText.send(player, auth.message("database.error"));
                    return;
                }
                emailChallenges.remove("recover:" + lower);
                session.registered = true;
                completeLogin(player, session, result.auth(),
                    () -> MinecraftText.send(player, auth.message("email.recoveryPassword")));
            }))
            .exceptionally(error -> {
                executeMain(() -> { clearAuthentication(session); MinecraftText.send(player, auth.message("database.error")); });
                return null;
            });
    }

    private String recoveryCode() {
        int length = cfg().emailRecoveryCodeLength();
        StringBuilder code = new StringBuilder(length);
        for (int i = 0; i < length; i++) code.append(secureRandom.nextInt(10));
        return code.toString();
    }

    private static boolean constantTimeEquals(String left, String right) {
        if (left == null || right == null) return false;
        return java.security.MessageDigest.isEqual(left.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
            right.trim().getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    public void emailShow(ServerPlayer player) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("not_logged_in"));
            return;
        }
        CompletableFuture
            .supplyAsync(() -> ds().lookupAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (!current(player, session)) return;
                if (!a.successful()) { MinecraftText.send(player, auth.message("database.error")); return; }
                if (a.auth() == null) { MinecraftText.send(player, auth.message("unknown_user", "player", realName(player))); return; }
                MinecraftText.send(player, auth.message("email.show", "email", displayEmail(a.auth().getEmail())));
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
                executeMain(() -> invalidateRemovedAccountSession(targetLower));
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
                invalidateRemovedAccountSession(targetLower);
            }
            reply.accept(auth.message(key, "player", targetLower));
        })).exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    /** Removes an online session after its account row was deleted, without persisting logout data. */
    private void invalidateRemovedAccountSession(String targetLower) {
        PlayerSession online = sessions.get(targetLower);
        if (online == null) return;
        online.authenticated = false;
        online.pendingTotp = false;
        online.active = false;
        online.loginGeneration++;
        ServerPlayer player = onlinePlayer(online.uuid);
        if (player != null) {
            setBlindEffect(player, false);
            restoreLimbo(player, online);
            kick(player, auth.message("unregister.success"));
        } else {
            restoreLimbo(null, online);
            limboStore.remove(online.uuid);
        }
        sessions.remove(targetLower, online);
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
        PlayerSession targetSession = sessions.get(targetLower);
        if (!canBeForced(targetSession)) {
            reply.accept(auth.message("admin.notAllowed"));
            return;
        }
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
                        restoreLimbo(p, online);
                        JoinLeaveMessageBridge.onAuthenticated(p);
                        setBlindEffect(p, false);
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
                        online.frozenX = p.getX();
                        online.frozenY = p.getY();
                        online.frozenZ = p.getZ();
                        online.frozenWorld = worldKey(p);
                        online.joinTime = System.currentTimeMillis();
                        enterLimbo(p, online);
                        applyPermissionGroup(p, online);
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
        java.util.Set<String> bypassNames = snapshotPurgeBypassNames();
        boolean onlineMode = auth.server() != null && auth.server().usesAuthentication();
        CompletableFuture.supplyAsync(() -> purgeOld(cutoff, bypassNames, onlineMode)).thenAccept(result -> executeMain(() -> reply.accept(result.operation().successful() ? auth.message("admin.purged", "count", result.operation().affected()) : auth.message("database.error"))));
    }

    private void runAutoPurge() {
        long cutoff = System.currentTimeMillis() - cfg().purgeDays() * 86_400_000L;
        java.util.Set<String> bypassNames = snapshotPurgeBypassNames();
        boolean onlineMode = auth.server() != null && auth.server().usesAuthentication();
        CompletableFuture.supplyAsync(() -> purgeOld(cutoff, bypassNames, onlineMode))
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
        boolean onlineMode = auth.server() != null && auth.server().usesAuthentication();
        CompletableFuture.supplyAsync(() -> {
            DataSource.LookupResult lookup = ds().lookupAuth(targetLower);
            if (!lookup.successful()) return new PurgeResult(new DataSource.OperationResult(0, false), List.of(), 0);
            if (lookup.auth() == null) return new PurgeResult(new DataSource.OperationResult(0, true), List.of(), 0);
            if (!force) return new PurgeResult(new DataSource.OperationResult(-1, true), List.of(lookup.auth()), 0);
            boolean removed = ds().removeAuth(targetLower);
            int files = removed ? PurgeFileCleaner.clean(FabricLoader.getInstance().getGameDir(), cfg(), List.of(lookup.auth()), onlineMode) : 0;
            return new PurgeResult(new DataSource.OperationResult(removed ? 1 : 0, true), List.of(lookup.auth()), files);
        }).thenAccept(result -> executeMain(() -> {
            if (!result.operation().successful()) reply.accept(auth.message("database.error"));
            else if (result.operation().affected() < 0) reply.accept(auth.message("admin.purgePlayerConfirm", "player", targetLower));
            else if (result.operation().affected() > 0) reply.accept(auth.message("admin.purgedPlayer", "player", targetLower));
            else reply.accept(auth.message("admin.playerNotFound", "player", targetLower));
        })).exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
    }

    private PurgeResult purgeOld(long cutoff, java.util.Set<String> bypassNames, boolean onlineMode) {
        DataSource.QueryResult<List<PlayerAuth>> candidates = ds().queryPurgeCandidates(cutoff, 10000);
        if (!candidates.successful()) return new PurgeResult(new DataSource.OperationResult(0, false), List.of(), 0);
        List<PlayerAuth> removable = candidates.value().stream()
            .filter(account -> !bypassesPurge(account, bypassNames)).toList();
        List<PlayerAuth> removedAccounts = new java.util.ArrayList<>();
        boolean successful = true;
        for (PlayerAuth account : removable) {
            DataSource.OperationResult removed = ds().removeAuthIfUnchanged(account, cutoff);
            if (!removed.successful()) {
                successful = false;
                break;
            }
            if (removed.affected() > 0) removedAccounts.add(account);
        }
        DataSource.OperationResult operation = new DataSource.OperationResult(
            removedAccounts.size(), successful);
        int files = successful ? PurgeFileCleaner.clean(FabricLoader.getInstance().getGameDir(), cfg(), removedAccounts, onlineMode) : 0;
        return new PurgeResult(operation, removedAccounts, files);
    }

    private java.util.Set<String> snapshotPurgeBypassNames() {
        java.util.Set<String> names = new java.util.HashSet<>();
        for (PlayerSession session : sessions.values()) {
            ServerPlayer online = session == null ? null : onlinePlayer(session.uuid);
            if (online != null && hasAuthMePermission(online, "authme.bypasspurge")) {
                names.add(session.name.toLowerCase(Locale.ROOT));
            }
        }
        return java.util.Set.copyOf(names);
    }

    private static boolean bypassesPurge(PlayerAuth account, java.util.Set<String> bypassNames) {
        return account != null && account.getName() != null && bypassNames != null
            && bypassNames.contains(account.getName().toLowerCase(Locale.ROOT));
    }

    public void purgeBannedPlayers(Consumer<String> reply) {
        executeMain(() -> {
            java.util.Set<String> banned = auth.server() == null ? java.util.Set.of()
                : BanListBridge.names(auth.server().getPlayerList());
            boolean onlineMode = auth.server() != null && auth.server().usesAuthentication();
            CompletableFuture.supplyAsync(() -> {
            int removed = 0;
            java.util.List<PlayerAuth> purged = new java.util.ArrayList<>();
            for (String name : banned) {
                DataSource.LookupResult lookup = ds().lookupAuth(name);
                if (lookup.successful() && lookup.auth() != null && ds().removeAuth(name)) { removed++; purged.add(lookup.auth()); }
            }
            PurgeFileCleaner.clean(FabricLoader.getInstance().getGameDir(), cfg(), purged, onlineMode);
            return removed;
            }).thenAccept(count -> executeMain(() -> reply.accept(auth.message("admin.purgedBanned", "count", count))))
                .exceptionally(error -> { executeMain(() -> reply.accept(auth.message("database.error"))); return null; });
        });
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
        if ("mysqldef".equals(section)) {
            DataSource.MySqlDefinitionOperation operation = null;
            if (arg1 != null) {
                try {
                    operation = DataSource.MySqlDefinitionOperation.valueOf(arg1.trim().toUpperCase(Locale.ROOT));
                } catch (IllegalArgumentException ignored) {
                    // Keep invalid operator input away from the SQL builder.
                }
            }
            if (operation == null || (operation != DataSource.MySqlDefinitionOperation.DETAILS
                && (arg2 == null || arg2.isBlank()))) {
                reply.accept("&7Usage: /authme debug mysqldef add|remove <LASTLOGIN|LASTIP|EMAIL>");
                reply.accept("&7       /authme debug mysqldef details");
                return;
            }
            DataSource.MySqlDefinitionOperation selected = operation;
            CompletableFuture.supplyAsync(() -> ds().mysqlDefinition(selected, arg2))
                .thenAccept(result -> executeMain(() -> {
                    if (!result.supported() || !result.successful()) reply.accept("&c" + result.error());
                    else result.lines().forEach(reply);
                }))
                .exceptionally(error -> {
                    executeMain(() -> reply.accept(auth.message("database.error")));
                    return null;
                });
            return;
        }
        if ("spawn".equals(section)) {
            reply.accept("&7spawn=" + spawnStore.get("spawn") + " firstSpawn=" + spawnStore.get("firstspawn")); return;
        }
        reply.accept("&cUnknown debug section '&f" + child + "&c'. Supported on Fabric: stats, db, cty, valid, mysqldef, spawn.");
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
                if (Files.isSymbolicLink(directory)) return null;
                io.github.authme.fabric.util.SecureFileAccess.ensurePrivateDirectory(directory);
                Path safeDirectory = directory.toAbsolutePath().normalize();
                Path file = safeDirectory.resolve("authme-" + java.time.format.DateTimeFormatter
                    .ofPattern("yyyyMMdd-HHmmss").withZone(java.time.ZoneOffset.UTC)
                    .format(java.time.Instant.now()) + ".sql");
                if (java.nio.file.Files.exists(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                    file = safeDirectory.resolve("authme-" + java.time.format.DateTimeFormatter
                        .ofPattern("yyyyMMdd-HHmmss").withZone(java.time.ZoneOffset.UTC)
                        .format(java.time.Instant.now()) + "-" + Long.toUnsignedString(System.nanoTime()) + ".sql");
                }
                if (!file.startsWith(safeDirectory)) return null;
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

    /** Records a successfully opened menu so the container-click guard can apply the configured exception. */
    public void recordInventoryOpen(ServerPlayer player, int containerId, String title) {
        if (player == null || !cfg().protectInventoryBeforeLogin() || !isUnauthenticated(player)) {
            if (player != null) unrestrictedInventoryRegistry.clear(player.getUUID());
            return;
        }
        unrestrictedInventoryRegistry.record(player.getUUID(), containerId, title);
    }

    public void clearInventoryOpen(ServerPlayer player) {
        if (player != null) unrestrictedInventoryRegistry.clear(player.getUUID());
    }

    public boolean allowInventoryClick(ServerPlayer player, int containerId) {
        return player != null && cfg().protectInventoryBeforeLogin() && isUnauthenticated(player)
            && unrestrictedInventoryRegistry.allows(player.getUUID(), containerId,
                cfg().unrestrictedInventories());
    }

    /** Allows the initial right-click only when the targeted block exposes a configured menu title. */
    public boolean allowUnrestrictedBlock(ServerPlayer player, Object level, BlockPos pos) {
        if (player == null || !(level instanceof Level actualLevel) || pos == null || !cfg().protectInventoryBeforeLogin()
            || !isUnauthenticated(player)) return false;
        if (!(actualLevel.getBlockEntity(pos) instanceof MenuProvider provider)) return false;
        return UnrestrictedInventoryRegistry.matches(provider.getDisplayName().getString(),
            cfg().unrestrictedInventories());
    }

    /** Allows entity-backed menus (for example a modded NPC menu) with a configured title. */
    public boolean allowUnrestrictedEntity(ServerPlayer player, Entity entity) {
        if (player == null || entity == null || !cfg().protectInventoryBeforeLogin()
            || !isUnauthenticated(player) || !(entity instanceof MenuProvider provider)) return false;
        return UnrestrictedInventoryRegistry.matches(provider.getDisplayName().getString(),
            cfg().unrestrictedInventories());
    }

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

    /** AuthMe's explicit exception for chat before authentication. */
    public boolean allowChatBeforeLogin(ServerPlayer player) {
        return !isUnauthenticated(player) || cfg().allowChat()
            || hasAuthMePermission(player, "authme.allowchatbeforelogin");
    }

    /** Sends AntiBot lifecycle notices only to players with the upstream admin visibility node. */
    public void notifyAntiBotAdmins(String key, Object... replacements) {
        MinecraftServer server = auth.server();
        if (server == null || key == null || key.isBlank()) return;
        for (ServerPlayer online : server.getPlayerList().getPlayers()) {
            if (hasAuthMePermission(online, "authme.admin.antibotmessages")) {
                MinecraftText.send(online, auth.message(key, replacements));
            }
        }
    }

    /** Returns whether the chat broadcast should omit this viewer. */
    public boolean hideChatFrom(ServerPlayer viewer) {
        return viewer != null && cfg().hideChat() && isUnauthenticated(viewer);
    }

    /** The player-scoped account privacy permission, separate from admin diagnostics. */
    public boolean canSeeOwnAccounts(ServerPlayer player) {
        return hasAuthMePermission(player, "authme.player.seeownaccounts");
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
        PlayerSession session = player == null ? null : sessions.get(realName(player).toLowerCase(Locale.ROOT));
        long quickDelay = cfg().quickCommandsDenyBeforeMilliseconds();
        if (session != null && !session.authenticated && quickDelay > 0L
            && System.currentTimeMillis() - session.joinTime < quickDelay
            && quickCommandProtectionEnabled(player)) {
            kick(player, auth.message("quickcommands.tooFast"));
            return false;
        }
        return CommandTokenPolicy.isAllowed(rootToken, cfg().allowedCommands());
    }

    private boolean quickCommandProtectionEnabled(ServerPlayer player) {
        if (player == null) return false;
        return QuickCommandPolicy.enabled(cfg().permissionCheckEnabled(),
            hasAuthMePermission(player, "authme.player.protection.quickcommandsprotection"),
            PermissionBridge.providerPresent());
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
            if (s.authenticated) {
                if (tickCounter % 100 == 0) checkLoginLease(p, s);
                continue;
            }
            if (!cfg().restrictUnauthenticated()) {
                if (s.limboCaptured) restoreLimbo(p, s);
                setBlindEffect(p, false);
                continue;
            }
            if (!s.accountResolved) {
                if (!cfg().allowMovement()) {
                    double dx = p.getX() - s.frozenX;
                    double dy = p.getY() - s.frozenY;
                    double dz = p.getZ() - s.frozenZ;
                    double radius = Math.max(0.0, cfg().allowedMovementRadius());
                    if (radius > 0.0d && (dx * dx + dz * dz > radius * radius || Math.abs(dy) > 0.1)) {
                        p.teleportTo(p.level(), s.frozenX, s.frozenY, s.frozenZ,
                            java.util.Set.of(), p.getYRot(), p.getXRot(), false);
                    }
                }
                if (cfg().removeSpeed()) p.setDeltaMovement(Vec3.ZERO);
                continue;
            }
            if (!s.registered && !cfg().registrationForce()) {
                restoreLimbo(p, s);
                setBlindEffect(p, false);
                continue;
            }
            // freeze
            if (!cfg().allowMovement()) {
                double dx = p.getX() - s.frozenX;
                double dy = p.getY() - s.frozenY;
                double dz = p.getZ() - s.frozenZ;
                double radius = Math.max(0.0, cfg().allowedMovementRadius());
                double horiz = dx * dx + dz * dz;
                if (radius > 0.0d && (horiz > radius * radius || Math.abs(dy) > 0.1)) {
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
            long cutoff = System.currentTimeMillis()
                - Math.max(60L, cfg().emailRecoveryCooldownSeconds()) * 2_000L;
            emailRecoveryLastSent.entrySet().removeIf(e -> e.getValue() < cutoff);
        }
    }

    // ===================================================================== internals

    private void checkLoginLease(ServerPlayer player, PlayerSession session) {
        if (session.loginLeaseCheckInFlight || session.lastLogin <= 0L) return;
        session.loginLeaseCheckInFlight = true;
        long expected = session.lastLogin;
        CompletableFuture.supplyAsync(() -> ds().renewLoginLease(
            session.name, expected, System.currentTimeMillis())).thenAccept(result ->
            executeMain(() -> {
                session.loginLeaseCheckInFlight = false;
                if (!session.active || sessions.get(session.name) != session || offline(player)
                    || !session.authenticated || session.lastLogin != expected) return;
                if (!result.successful()) {
                    failDatabase(player, session);
                    return;
                }
                if (!result.active() && cfg().forceSingleSession()) {
                    session.authenticated = false;
                    kick(player, "Your AuthMe account was logged in from another location.");
                }
            }));
    }

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

    private record ScheduledCommand(long dueTick, ServerPlayer player, PlayerSession session,
                                    EventCommands.ConfiguredCommand command, String text) { }

    private void runEventCommands(String event, ServerPlayer player) {
        if (player == null) return;
        PlayerSession eventSession = sessions.get(realName(player).toLowerCase(Locale.ROOT));
        for (EventCommands.ConfiguredCommand command : eventCommands.get(event)) {
            if (command.accountsAtLeast() < 0 && command.accountsLessThan() < 0) {
                if (eventSession != null && !current(player, eventSession)) return;
                scheduleCommand(player, eventSession, command);
                continue;
            }
            CompletableFuture.supplyAsync(() -> ds().queryRegisteredNamesByIp(ip(player))).thenAccept(result -> executeMain(() -> {
                // The account-count query may finish after disconnect/reconnect. Do not
                // execute an event belonging to an obsolete player session.
                if (eventSession != null && !current(player, eventSession)) return;
                if (!result.successful()) return;
                int count = result.value().size();
                if (command.accountsAtLeast() >= 0 && count < command.accountsAtLeast()) return;
                if (command.accountsLessThan() >= 0 && count >= command.accountsLessThan()) return;
                scheduleCommand(player, eventSession, command);
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
            try {
                server.getCommands().performPrefixedCommand(server.createCommandSourceStack().withSuppressedOutput(), command);
            } catch (RuntimeException e) {
                Log.warn("Configured AuthMe AntiBot command failed", e);
            }
        }
    }

    private void scheduleCommand(ServerPlayer player, PlayerSession session,
                                  EventCommands.ConfiguredCommand command) {
        String text = command.command().replace("%p", realName(player).toLowerCase(Locale.ROOT)).replace("%nick", realName(player)).replace("%ip", ip(player)).replace("%country", "");
        if (command.delayTicks() <= 0) executeEventCommand(player, command, text);
        else if (scheduledCommands.size() < MAX_SCHEDULED_COMMANDS) {
            scheduledCommands.add(new ScheduledCommand(tickCounter + command.delayTicks(), player, session, command, text));
        }
    }

    private void runScheduledCommands() {
        for (ScheduledCommand scheduled : scheduledCommands) {
            if (scheduled.dueTick() > tickCounter) continue;
            scheduledCommands.remove(scheduled);
            boolean valid = scheduled.session() == null
                ? !offline(scheduled.player())
                : current(scheduled.player(), scheduled.session());
            if (valid) executeEventCommand(scheduled.player(), scheduled.command(), scheduled.text());
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

    private boolean isUnrestrictedName(String lower) {
        if (lower == null) return false;
        for (String configured : cfg().unrestrictedNames()) {
            if (configured != null && lower.equals(configured.trim().toLowerCase(Locale.ROOT))) return true;
        }
        return false;
    }

    private boolean validPassword(String password) {
        if (password == null || password.length() < cfg().minPasswordLength()
            || password.length() > cfg().maxPasswordLength()
            || cfg().unsafePasswords().contains(password.toLowerCase(Locale.ROOT))) return false;
        try { return password.matches(cfg().allowedPasswordCharacters()); }
        catch (RuntimeException e) { return false; }
    }

    private String displayEmail(String email) {
        if (email == null || email.isBlank() || !cfg().emailMaskingEnabled()) return email == null ? "" : email;
        int at = email.lastIndexOf('@');
        if (at <= 0 || at >= email.length() - 1) return "***";
        String local = email.substring(0, at);
        String domain = email.substring(at + 1);
        String localMasked = local.length() <= 2
            ? local.substring(0, 1) + "***"
            : local.charAt(0) + "***" + local.charAt(local.length() - 1);
        int dot = domain.lastIndexOf('.');
        String host = dot > 0 ? domain.substring(0, dot) : domain;
        String suffix = dot > 0 ? domain.substring(dot) : "";
        String hostMasked = host.isEmpty() ? "***" : host.charAt(0) + "***";
        return localMasked + "@" + hostMasked + suffix;
    }

    private boolean validEmailDomain(String email) {
        if (!EmailAddressPolicy.isValid(email)) return false;
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
            // The replacement login fence invalidates the old connection without clearing itself.
        }
    }

    private void displayOtherAccounts(ServerPlayer player, String address) {
        CompletableFuture.supplyAsync(() -> ds().queryRegisteredNamesByIp(address)).thenAccept(result -> executeMain(() -> {
                if (!result.successful() || result.value().size() <= 1
                    || result.value().size() <= cfg().otherAccountsThreshold()) return;
            MinecraftText.send(player, auth.message("admin.otherAccounts", "accounts", String.join(", ", result.value())));
            String configured = cfg().otherAccountsCommand();
            if (!configured.isBlank() && result.value().size() > cfg().otherAccountsCommandThreshold()
                && auth.server() != null) {
                String command = configured.replace("%playername%", realName(player))
                    .replace("%playerip%", ip(player)).replace("%p", realName(player))
                    .replace("%nick", realName(player)).replace("%ip", ip(player));
                if (command.startsWith("/")) command = command.substring(1);
                auth.server().getCommands().performPrefixedCommand(
                    auth.server().createCommandSourceStack().withSuppressedOutput(), command);
            }
        }));
    }

    private int recordLoginFailure(String playerName, String address) {
        long now = System.currentTimeMillis();
        DataSource.FailureStateResult account = ds().recordFailureState(
            accountFailureStateKey(playerName, address), now,
            failureWindowMillis(), cfg().tempbanEnabled() ? cfg().tempbanMaxLoginTries() : 0,
            Math.max(1L, cfg().tempbanLengthMinutes()) * 60_000L);
        DataSource.FailureStateResult source = ds().recordFailureState(
            sourceFailureStateKey(address), now,
            failureWindowMillis(), cfg().tempbanEnabled() ? cfg().tempbanMaxLoginTries() : 0,
            Math.max(1L, cfg().tempbanLengthMinutes()) * 60_000L);
        if (!account.successful() || !source.successful()) return Integer.MAX_VALUE;
        if (cfg().tempbanEnabled()
            && (account.bannedUntil() > now || source.bannedUntil() > now)) {
            return Math.max(account.attempts(), cfg().tempbanMaxLoginTries());
        }
        return account.attempts();
    }

    private long failureWindowMillis() {
        long minutes = cfg().tempbanEnabled()
            ? cfg().tempbanCounterResetMinutes() : cfg().captchaResetMinutes();
        return Math.max(1L, minutes) * 60_000L;
    }

    private static String accountFailureStateKey(String playerName, String address) {
        String normalizedName = playerName == null ? "unknown" : playerName.toLowerCase(Locale.ROOT);
        return "auth|" + normalizedName + '|' + normalizeIp(address);
    }

    private static String sourceFailureStateKey(String address) {
        return "ip|" + normalizeIp(address);
    }

    private synchronized void rememberUnsafeIpBlock(String key) {
        if (key == null || key.isBlank()) return;
        if (unsafeIpBlocks.size() >= MAX_UNSAFE_IP_BLOCKS && !unsafeIpBlocks.contains(key)) {
            java.util.Iterator<String> iterator = unsafeIpBlocks.iterator();
            if (iterator.hasNext()) unsafeIpBlocks.remove(iterator.next());
        }
        unsafeIpBlocks.add(key);
    }

    private void applyTempban(ServerPlayer player, String address) {
        String configured = cfg().tempbanCustomCommand();
        if (configured == null || configured.isBlank()) return;
        MinecraftServer server = auth.server();
        if (server == null) return;
        String command = configured.replace("%player%", realName(player)).replace("%p", realName(player))
            .replace("%nick", realName(player)).replace("%ip%", address == null ? "" : address)
            .replace("%ip", address == null ? "" : address);
        if (command.startsWith("/")) command = command.substring(1);
        try { server.getCommands().performPrefixedCommand(server.createCommandSourceStack().withSuppressedOutput(), command); }
        catch (RuntimeException e) { Log.error("Configured AuthMe tempban command failed; the shared internal ban remains active", e); }
    }

    private void clearLoginFailures(String playerName, String address) {
        CompletableFuture.runAsync(() -> ds().clearFailureState(
            accountFailureStateKey(playerName, address)));
    }

    private static void recordTotpFailure(PlayerSession session) {
        if (session == null) return;
        int attempts = ++session.totpAttempts;
        if (attempts >= 5) {
            long delay = Math.min(60_000L, 5_000L << Math.min(4, attempts - 5));
            session.totpBlockedUntil = System.currentTimeMillis() + delay;
        }
    }

    private static void clearTotpFailures(PlayerSession session) {
        if (session != null) {
            session.totpAttempts = 0;
            session.totpBlockedUntil = 0L;
        }
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
        long loginAt = System.currentTimeMillis();
        long generation = ++session.loginGeneration;
        CompletableFuture.supplyAsync(() -> ds().acquireLoginState(lower, session.lastIp, loginAt,
            cfg().sessionEnabled(), cfg().maxLoginPerIp())).thenAccept(acquired -> executeMain(() -> {
            boolean saved = acquired.acquired();
            clearAuthentication(session);
            boolean stillCurrent = session.active && session.loginGeneration == generation
                && sessions.get(lower) == session && !offline(player);
            if (!saved || !stillCurrent) {
                if (saved && !stillCurrent) CompletableFuture.runAsync(() -> ds().clearLoginIfLastLogin(lower, acquired.version()));
                if (!saved && !offline(player)) {
                    if (acquired.status() == DataSource.LoginStateStatus.LIMIT_REACHED) {
                        MinecraftText.send(player, "Too many authenticated accounts from this address.");
                    } else failDatabase(player, session);
                }
                return;
            }
            session.authenticated = true;
            session.lastLogin = acquired.version();
            session.pendingTotp = false;
            JoinLeaveMessageBridge.onAuthenticated(player);
            applyConfiguredGameMode(player, true);
            clearLoginFailures(lower, session.lastIp);
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
            restoreLimbo(player, session);
            setBlindEffect(player, false);
            MinecraftText.send(player, auth.message("login.success"));
            sendWelcomeMessage(player, session);
            runEventCommands("onLogin", player);
            auth.emitProxyMessage(ProxyProtocol.LOGIN, lower);
            auth.connectPlayerToConfiguredServer(player);
            if (authRow.getLastLogin() == null || authRow.getLastLogin() <= 0L) runEventCommands("onFirstLogin", player);
            if (cfg().displayOtherAccounts()
                && (hasAuthMePermission(player, "authme.admin.seeotheraccounts")
                    || canSeeOwnAccounts(player))) {
                displayOtherAccounts(player, session.lastIp);
            }
            if (onSuccess != null) onSuccess.run();
        })).exceptionally(error -> { executeMain(() -> failDatabase(player, session)); return null; });
    }

    /** Captures and applies the temporary unauthenticated-player sandbox. */
    private void enterLimbo(ServerPlayer player, PlayerSession session) {
        if (!cfg().restrictUnauthenticated()) return;
        LimboStateStore.State persisted = limboStore.load(session.uuid);
        if (persisted != null) {
            session.originalOperator = persisted.operator();
            session.originalMayFly = persisted.mayFly();
            session.originalFlying = persisted.flying();
            session.originalWalkingSpeed = persisted.walkingSpeed();
            session.originalFlyingSpeed = persisted.flyingSpeed();
            session.originalInvulnerable = persisted.invulnerable();
        } else {
            session.originalOperator = isOperator(player);
            session.originalMayFly = player.getAbilities().mayfly;
            session.originalFlying = player.getAbilities().flying;
            session.originalWalkingSpeed = player.getAbilities().getWalkingSpeed();
            session.originalFlyingSpeed = player.getAbilities().getFlyingSpeed();
            session.originalInvulnerable = player.isInvulnerable();
        }
        session.limboCaptured = true;
        limboStore.save(session.uuid, new LimboStateStore.State(session.originalOperator,
            session.originalMayFly, session.originalFlying, session.originalWalkingSpeed,
            session.originalFlyingSpeed, session.originalInvulnerable));
        if (session.originalOperator) setOperator(player, false);
        if (!"NOTHING".equals(cfg().limboRestoreAllowFlight())) {
            player.getAbilities().mayfly = false;
            player.getAbilities().flying = false;
        }
        if (!"NOTHING".equals(cfg().limboRestoreWalkSpeed())
            || !"NOTHING".equals(cfg().limboRestoreFlySpeed())) {
            player.getAbilities().setWalkingSpeed(0.0f);
            player.getAbilities().setFlyingSpeed(0.0f);
        }
        notifyAbilities(player);
        player.setInvulnerable(true);
    }

    private void applyPermissionGroup(ServerPlayer player, PlayerSession session) {
        if (!cfg().groupOptionsEnabled() || player == null) return;
        String group = session.registered ? cfg().registeredPlayerGroup() : cfg().unregisteredPlayerGroup();
        if (group.isBlank()) return;
        session.groupSnapshot = PermissionBridge.applyGroup(player.getUUID(), group);
        if (PermissionBridge.providerPresent() && !session.groupSnapshot.applied()) {
            Log.warn("Could not switch " + realName(player) + " to AuthMe group '" + group + "'.");
        }
    }

    /** Restores all temporary limbo changes, including after an ordinary disconnect. */
    private void restoreLimbo(ServerPlayer player, PlayerSession session) {
        if (session == null) return;
        if (session.groupSnapshot != null) {
            if (!PermissionBridge.restoreGroup(session.uuid, session.groupSnapshot)) {
                Log.warn("Could not restore the permission group for " + session.name);
            }
            session.groupSnapshot = null;
        }
        if (!session.limboCaptured || player == null) {
            limboEnderPearls.remove(session.uuid);
            return;
        }
        restoreLimboEnderPearls(player, session);
        String allowFlight = cfg().limboRestoreAllowFlight();
        if (!"NOTHING".equals(allowFlight)) {
            boolean mayFly = switch (allowFlight) {
                case "ENABLE" -> true;
                case "DISABLE" -> false;
                default -> session.originalMayFly;
            };
            player.getAbilities().mayfly = mayFly;
            player.getAbilities().flying = mayFly && session.originalFlying;
        }
        player.getAbilities().setWalkingSpeed(restoreSpeed(cfg().limboRestoreWalkSpeed(),
            session.originalWalkingSpeed, player.getAbilities().getWalkingSpeed(), 0.1f));
        player.getAbilities().setFlyingSpeed(restoreSpeed(cfg().limboRestoreFlySpeed(),
            session.originalFlyingSpeed, player.getAbilities().getFlyingSpeed(), 0.05f));
        notifyAbilities(player);
        setOperator(player, session.originalOperator);
        player.setInvulnerable(session.originalInvulnerable);
        limboStore.remove(session.uuid);
        session.limboCaptured = false;
    }

    private void restoreLimboEnderPearls(ServerPlayer player, PlayerSession session) {
        List<LimboEnderPearl> tracked = limboEnderPearls.remove(session.uuid);
        if (tracked == null || tracked.isEmpty() || !session.authenticated
            || !cfg().limboRecreateEnderPearls()) return;
        ServerLevel level = player.level();
        for (LimboEnderPearl snapshot : tracked) {
            if (!snapshot.entity().isRemoved() || snapshot.level() != level) continue;
            try {
                ThrownEnderpearl replacement = new ThrownEnderpearl(level, player,
                    new ItemStack(Items.ENDER_PEARL));
                replacement.setPos(snapshot.x(), snapshot.y(), snapshot.z());
                replacement.setDeltaMovement(snapshot.velocity());
                replacement.setYRot(snapshot.yaw());
                replacement.setXRot(snapshot.pitch());
                level.addFreshEntity(replacement);
            } catch (RuntimeException error) {
                Log.warn("Could not recreate an ender pearl for " + session.name, error);
            }
        }
    }

    private static float restoreSpeed(String mode, float original, float current, float defaultSpeed) {
        return switch (mode) {
            case "DEFAULT" -> defaultSpeed;
            case "MAX_RESTORE" -> Math.max(current, original);
            case "RESTORE_NO_ZERO" -> original == 0.0f ? defaultSpeed : original;
            case "NOTHING" -> current;
            default -> original;
        };
    }

    private boolean isOperator(ServerPlayer player) {
        if (player == null || auth.server() == null) return false;
        try {
            Object ops = auth.server().getPlayerList().getClass().getMethod("getOps")
                .invoke(auth.server().getPlayerList());
            Object profile = player.getGameProfile();
            Object key = operatorKey(player);
            Object entry = invokeOne(ops, "get", key);
            if (entry == null && key != profile) entry = invokeOne(ops, "get", profile);
            return entry != null;
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            try {
                return Boolean.TRUE.equals(player.getClass().getMethod("hasPermissions", int.class)
                    .invoke(player, 2));
            } catch (ReflectiveOperationException ignoredAgain) {
                return false;
            }
        }
    }

    private void setOperator(ServerPlayer player, boolean operator) {
        if (player == null || auth.server() == null) return;
        try {
            Object list = auth.server().getPlayerList();
            Object profile = player.getGameProfile();
            Object key = operatorKey(player);
            java.lang.reflect.Method method = findOne(list, operator ? "op" : "deop", key);
            Object argument = key;
            if (method == null && key != profile) {
                method = findOne(list, operator ? "op" : "deop", profile);
                argument = profile;
            }
            if (method != null) method.invoke(list, argument);
        } catch (ReflectiveOperationException | RuntimeException e) {
            Log.warn("Could not restore AuthMe operator state for " + realName(player), e);
        }
    }

    /** 1.21.x stores operator entries as NameAndId; older lines use GameProfile. */
    private static Object operatorKey(ServerPlayer player) throws ReflectiveOperationException {
        Object profile = player.getGameProfile();
        try {
            Class<?> nameAndId = Class.forName("net.minecraft.server.players.NameAndId");
            return nameAndId.getConstructor(com.mojang.authlib.GameProfile.class).newInstance(profile);
        } catch (ClassNotFoundException | NoSuchMethodException e) {
            return profile;
        }
    }

    private static Object invokeOne(Object target, String name, Object value)
        throws ReflectiveOperationException {
        if (target == null || value == null) return null;
        java.lang.reflect.Method method = findOne(target, name, value);
        return method == null ? null : method.invoke(target, value);
    }

    private static java.lang.reflect.Method findOne(Object target, String name, Object value) {
        if (target == null || value == null) return null;
        for (java.lang.reflect.Method method : target.getClass().getMethods()) {
            if (method.getName().equals(name) && method.getParameterCount() == 1
                && method.getParameterTypes()[0].isAssignableFrom(value.getClass())) return method;
        }
        return null;
    }

    private static void notifyAbilities(ServerPlayer player) {
        try {
            java.lang.reflect.Method method = player.getClass().getMethod("onUpdateAbilities");
            method.invoke(player);
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // Ability fields are still updated locally on mappings without the helper method.
        }
    }

    private void kick(ServerPlayer player, String message) {
        try {
            player.connection.disconnect(MinecraftText.toComponent(player, message));
        } catch (Exception e) {
            Log.error("Failed to disconnect " + realName(player), e);
        }
    }

    private void setBlindEffect(ServerPlayer player, boolean enabled) {
        if (player == null) return;
        PlayerSession session = sessions.get(realName(player).toLowerCase(Locale.ROOT));
        if (enabled) {
            if (!cfg().applyBlindEffect() || session == null || player.hasEffect(MobEffects.BLINDNESS)) return;
            if (player.addEffect(new MobEffectInstance(MobEffects.BLINDNESS, Integer.MAX_VALUE, 0, false, false, false))) {
                session.authMeBlindEffect = true;
            }
        }
        else if (session != null && session.authMeBlindEffect) {
            player.removeEffect(MobEffects.BLINDNESS);
            session.authMeBlindEffect = false;
        }
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

    public void disconnectAllForDatabaseFailure() {
        for (PlayerSession current : sessions.values()) {
            current.authenticated = false;
            current.pendingTotp = false;
            current.authenticationBusy = false;
        }
        MinecraftServer server = auth.server();
        if (server == null) return;
        for (ServerPlayer online : server.getPlayerList().getPlayers()) {
            MinecraftText.send(online, auth.message("database.error"));
            kick(online, auth.message("database.error"));
        }
    }

    private void failDatabase(ServerPlayer player, PlayerSession session) {
        // An old async callback must not fail closed for a newer connection.
        if (!current(player, session)) return;
        clearAuthentication(session);
        session.authenticated = false;
        session.pendingTotp = false;
        auth.databaseFailure("a runtime authentication operation failed");
    }

    private void notifyDatabaseError(UUID uuid) {
        ServerPlayer player = onlinePlayer(uuid);
        if (player != null) MinecraftText.send(player, auth.message("database.error"));
    }


    // ===================================================================== small helpers

    /** Serialize authentication-changing commands while their database work is asynchronous. */
    private boolean beginAuthentication(ServerPlayer player, PlayerSession session) {
        if (session == null || !session.active) return false;
        if (session.authenticationBusy) {
            MinecraftText.send(player, auth.message("auth.pending"));
            return false;
        }
        session.authenticationBusy = true;
        return true;
    }

    private static void clearAuthentication(PlayerSession session) {
        if (session != null) session.authenticationBusy = false;
    }

    private <T> void executeMain(Runnable r) {
        MinecraftServer s = auth.server();
        if (s != null) s.execute(r);
        else r.run();
    }

    private boolean offline(ServerPlayer p) {
        if (auth.server() == null || p == null) return true;
        return auth.server().getPlayerList().getPlayer(p.getUUID()) != p;
    }

    private boolean current(ServerPlayer player, PlayerSession session) {
        return session != null && session.active && sessions.get(session.name) == session && !offline(player);
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

    private boolean hasAuthMePermission(ServerPlayer player, String node) {
        if (player == null || node == null || node.isBlank()) return false;
        if (player.hasPermissions(2)) return true;
        if (!cfg().permissionCheckEnabled()) return false;
        if (Boolean.TRUE.equals(PermissionBridge.check(player.getUUID(), node))) return true;
        if (node.startsWith("authme.player.")
            && Boolean.TRUE.equals(PermissionBridge.check(player.getUUID(), "authme.player.*"))) return true;
        return node.startsWith("authme.admin.")
            && Boolean.TRUE.equals(PermissionBridge.check(player.getUUID(), "authme.admin.*"));
    }

    /** VIP is intentionally a dedicated status node; operator/admin wildcards do not grant it. */
    private boolean hasVipPermission(ServerPlayer player) {
        return player != null && cfg().permissionCheckEnabled()
            && Boolean.TRUE.equals(PermissionBridge.check(player.getUUID(), "authme.vip"));
    }

    private boolean canBeForced(PlayerSession session) {
        if (session == null) return true;
        ServerPlayer player = onlinePlayer(session.uuid);
        return player == null || hasAuthMePermission(player, "authme.player.canbeforced");
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
