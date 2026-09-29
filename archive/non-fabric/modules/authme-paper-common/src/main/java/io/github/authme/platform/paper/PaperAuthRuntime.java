package io.github.authme.platform.paper;

import io.github.authme.fabric.config.AuthMeConfig;
import io.github.authme.fabric.config.EventCommands;
import io.github.authme.fabric.config.GeoIpPolicy;
import io.github.authme.fabric.config.Messages;
import io.github.authme.fabric.config.SpawnLocation;
import io.github.authme.fabric.config.SpawnStore;
import io.github.authme.fabric.config.WelcomeMessage;
import io.github.authme.fabric.antibot.AntiBotManager;
import io.github.authme.fabric.auth.LimboStateStore;
import io.github.authme.fabric.auth.QuickCommandPolicy;
import io.github.authme.fabric.util.PermissionBridge;
import io.github.authme.fabric.datasource.DataSource;
import io.github.authme.fabric.datasource.PlayerAuth;
import io.github.authme.platform.PlatformAuthService;
import org.bukkit.Location;
import org.bukkit.GameMode;
import org.bukkit.entity.Player;
import org.bukkit.command.CommandSender;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.potion.PotionEffect;
import org.bukkit.potion.PotionEffectType;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Bukkit-family runtime that keeps platform callbacks separate from account I/O. */
public final class PaperAuthRuntime implements AutoCloseable {

    private static final int MAX_SESSIONS = 16_384;
    private static final int MAX_PRE_JOIN_HANDOFFS = 8_192;
    private static final int MAX_JOIN_ADDRESS_KEYS = 8_192;
    private final JavaPlugin plugin;
    private final PlatformScheduler scheduler;
    private final PlatformAuthService service;
    private final SpawnStore spawnStore;
    private final LimboStateStore limboStore;
    private final EventCommands eventCommands;
    private volatile AntiBotManager antiBot;
    private volatile GeoIpPolicy geoIp;
    private final boolean onlineMode;
    private final Map<UUID, Session> sessions = new ConcurrentHashMap<>();
    /** Bounded, short-lived connection-phase handoff; values may contain a submitted password. */
    private final Map<UUID, PreJoinHandoff> preJoinHandoffs = new ConcurrentHashMap<>();
    private final Set<UUID> busy = ConcurrentHashMap.newKeySet();
    private final Map<String, AtomicInteger> joinedByAddress = new ConcurrentHashMap<>();
    private final Object singleSessionLock = new Object();
    private final Object maintenanceLock = new Object();
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile List<String> welcomeLines = List.of();
    private volatile Messages messages;

    private PaperAuthRuntime(JavaPlugin plugin, PlatformScheduler scheduler, PlatformAuthService service,
                             boolean onlineMode) {
        this.plugin = plugin;
        this.scheduler = scheduler;
        this.service = service;
        this.onlineMode = onlineMode;
        this.spawnStore = new SpawnStore(plugin.getDataFolder().toPath());
        this.limboStore = new LimboStateStore(service.config().configDir(),
            service.config().limboPersistence(), service.config().limboDistributionSize());
        this.eventCommands = new EventCommands(service.config().configDir());
        this.antiBot = new AntiBotManager(service.config());
        this.geoIp = new GeoIpPolicy(service.config());
        this.welcomeLines = WelcomeMessage.load(service.config());
        this.messages = loadMessages(service.config());
        scheduleAutomaticMaintenance();
    }

    public static PaperAuthRuntime start(JavaPlugin plugin, PlatformScheduler scheduler) throws Exception {
        Path dataDirectory = plugin.getDataFolder().toPath().toAbsolutePath().normalize();
        return new PaperAuthRuntime(plugin, scheduler, PlatformAuthService.start(dataDirectory),
            plugin.getServer().getOnlineMode());
    }

    public AuthMeConfig config() { return service.config(); }

    /** Message bundle used by Paper's connection-phase dialog listener. */
    public Messages dialogMessages() { return messages; }

    /** Read-only account lookup used before a Bukkit Player object exists. */
    public DataSource.LookupResult preJoinLookup(String name) { return service.lookup(name); }

    /**
     * Session/proxy integrations can authenticate during the join pipeline. A blocking dialog
     * must not race those integrations, so those configurations retain the normal post-join flow.
     */
    public boolean preJoinShouldSkip() {
        return config().sessionEnabled() || config().bungeecordHook();
    }

    public boolean preJoinPremiumMatches(PlayerAuth auth, UUID profileId) {
        return onlineMode && config().enablePremium() && auth != null && profileId != null
            && auth.getPremiumUuid() != null && profileId.equals(auth.getPremiumUuid());
    }

    public boolean preJoinUnrestricted(String name) {
        return name != null && config().unrestrictedNames().stream().anyMatch(value ->
            value != null && value.trim().equalsIgnoreCase(name.trim()));
    }

    public void storePreJoinLogin(UUID playerId, String password) {
        if (playerId == null || password == null) return;
        storePreJoinHandoff(playerId, new PreJoinHandoff(
            new PreJoinSubmission(PreJoinKind.LOGIN, password, ""), null, handoffExpiry()));
    }

    public void storePreJoinRegistration(UUID playerId, String first, String second) {
        if (playerId == null) return;
        storePreJoinHandoff(playerId, new PreJoinHandoff(new PreJoinSubmission(PreJoinKind.REGISTER,
            first == null ? "" : first, second == null ? "" : second), null, handoffExpiry()));
    }

    public void storePreJoinRecovery(UUID playerId, String email) {
        if (playerId == null || email == null) return;
        storePreJoinHandoff(playerId, new PreJoinHandoff(
            new PreJoinSubmission(PreJoinKind.RECOVERY, email, ""), null, handoffExpiry()));
    }

    public void storePreJoinKick(UUID playerId, String message) {
        if (playerId == null) return;
        storePreJoinHandoff(playerId, new PreJoinHandoff(null, message == null || message.isBlank()
            ? "Authentication dialog timed out." : message, handoffExpiry()));
    }

    public void clearPreJoin(UUID playerId) {
        if (playerId == null) return;
        preJoinHandoffs.remove(playerId);
    }

    private void storePreJoinHandoff(UUID playerId, PreJoinHandoff handoff) {
        long now = System.currentTimeMillis();
        synchronized (preJoinHandoffs) {
            preJoinHandoffs.entrySet().removeIf(entry -> entry.getValue().expiresAt() <= now);
            if (preJoinHandoffs.size() >= MAX_PRE_JOIN_HANDOFFS && !preJoinHandoffs.containsKey(playerId)) {
                // Never evict another connection's credentials to make room. The joining player
                // will fall back to the normal post-join authentication flow, which is fail-closed.
                return;
            }
            preJoinHandoffs.put(playerId, handoff);
        }
    }

    private long handoffExpiry() {
        long timeoutSeconds = Math.max(1L, config().dialogPreJoinTimeoutSeconds());
        return System.currentTimeMillis() + Math.min(660_000L, (timeoutSeconds + 60L) * 1000L);
    }

    /** Runs during Paper's asynchronous login event and fails closed on database errors. */
    public boolean databaseAvailableForJoin(String name) {
        return service.lookup(name).successful();
    }

    public void onJoin(Player player) {
        UUID playerId = player.getUniqueId();
        // Citizens and CombatTag-style fake players are identified by the same server-side
        // metadata marker used by AuthMe upstream. They are not real authentication subjects;
        // letting them enter the AuthMe limbo would break NPC combat and protection plugins.
        if (isNpc(player)) {
            clearPreJoin(playerId);
            return;
        }
        PreJoinHandoff handoff = preJoinHandoffs.remove(playerId);
        if (handoff != null && handoff.expiresAt() <= System.currentTimeMillis()) handoff = null;
        String preJoinKick = handoff == null ? null : handoff.kickMessage();
        PreJoinSubmission preJoinSubmission = handoff == null ? null : handoff.submission();
        if (preJoinKick != null) {
            player.kickPlayer(preJoinKick);
            return;
        }
        String ip = address(player);
        String playerName = player.getName();
        AntiBotManager gate = antiBot;
        if (gate.shouldBlockNewJoins() && !player.hasPermission("authme.bypassantibot")) {
            player.kickPlayer("AuthMe is temporarily protecting the server from connection abuse.");
            return;
        }
        gate.notifyJoin(ip);
        if (config().protectionEnabled() && config().protectionRegistered()
            && !countryAllowed(player, ip)) {
            player.kickPlayer("Your country is not allowed on this server.");
            return;
        }
        if (!service.isRestrictedAddressAllowed(playerName, ip)) {
            if (config().banUnsafeIp() && player.getAddress() != null
                && player.getAddress().getAddress() != null) {
                plugin.getServer().getBanList(org.bukkit.BanList.Type.IP).addBan(
                    player.getAddress().getAddress().getHostAddress(),
                    "AuthMe restricted account address", null, "AuthMe");
            }
            player.kickPlayer("This account may not join from the current address.");
            return;
        }
        if (sessions.size() >= MAX_SESSIONS && !sessions.containsKey(player.getUniqueId())) {
            player.kickPlayer("AuthMe is temporarily full; please reconnect.");
            return;
        }
        if (!reserveJoinAddress(ip)) {
            player.kickPlayer("Too many players are joining from this address.");
            return;
        }
        long connectionToken = service.beginConnection(playerName);
        if (connectionToken <= 0L) {
            releaseJoinAddress(ip);
            player.kickPlayer("AuthMe could not establish a secure connection session.");
            return;
        }
        Session session = new Session(player, player.getLocation(), ip, connectionToken);
        session.preJoinSubmission = preJoinSubmission;
        sessions.put(player.getUniqueId(), session);
        prepareLimbo(player, session);
        scheduler.runAsync(() -> {
            DataSource.LookupResult lookup = service.lookup(playerName);
            scheduler.runForPlayer(player, () -> {
                Session current = sessions.get(player.getUniqueId());
                if (current != session || !player.isOnline()) return;
                if (!lookup.successful()) {
                    player.kickPlayer("Authentication database unavailable.");
                    return;
                }
                current.registered = lookup.auth() != null;
                current.accountResolved = true;
                current.firstLogin = current.registered && (lookup.auth().getLastLogin() == null
                    || lookup.auth().getLastLogin() <= 0L);
                applyPermissionGroup(player, current);
                if (!current.registered && config().kickNonRegistered() && !isUnrestricted(player)) {
                    player.kickPlayer("You must register before joining this server.");
                    return;
                }
                if (!current.registered) {
                    finishJoin(player, current, PlatformAuthService.AccountResult.SESSION_INVALID,
                        PlatformAuthService.AccountResult.PREMIUM_UNAVAILABLE);
                    return;
                }
                // Session/Premium lookups are database operations. Keep them off the Paper
                // main thread and off Folia's player region thread; the generation check in
                // the service still prevents a delayed result from authenticating a replacement.
                scheduler.runAsync(() -> {
                    PlatformAuthService.AccountResult sessionLogin = service.sessionLoginIfConnection(
                        playerName, ip, current.connectionToken);
                    PlatformAuthService.AccountResult premiumLogin =
                        sessionLogin == PlatformAuthService.AccountResult.SESSION_INVALID
                            ? service.premiumLoginIfConnection(playerName, playerId, onlineMode,
                                ip, current.connectionToken)
                            : PlatformAuthService.AccountResult.PREMIUM_UNAVAILABLE;
                    scheduler.runForPlayer(player,
                        () -> finishJoin(player, current, sessionLogin, premiumLogin));
                });
            });
        });
    }

    /** Completes the non-blocking join state transition on the player's platform thread. */
    private void finishJoin(Player player, Session session,
                            PlatformAuthService.AccountResult sessionLogin,
                            PlatformAuthService.AccountResult premiumLogin) {
        Session current = sessions.get(player.getUniqueId());
        if (current != session || !player.isOnline()) return;
        if (sessionLogin == PlatformAuthService.AccountResult.DATABASE_ERROR
            || sessionLogin == PlatformAuthService.AccountResult.CONFIG_ERROR
            || premiumLogin == PlatformAuthService.AccountResult.DATABASE_ERROR
            || premiumLogin == PlatformAuthService.AccountResult.CONFIG_ERROR) {
            player.kickPlayer("Authentication database unavailable.");
            return;
        }
        boolean sessionRestored = sessionLogin == PlatformAuthService.AccountResult.SUCCESS;
        if (sessionRestored) {
            completeAuthentication(player, current, true);
        } else if (sessionLogin == PlatformAuthService.AccountResult.TOTP_REQUIRED
            || premiumLogin == PlatformAuthService.AccountResult.TOTP_REQUIRED) {
            current.totpPending = true;
        } else if (premiumLogin == PlatformAuthService.AccountResult.SUCCESS) {
            completeAuthentication(player, current, false);
        }
        runEventCommands("onJoin", player, current);
        if (sessionRestored) runEventCommands("onSessionLogin", player, current);
        if (isBlocked(player)) {
            player.sendMessage("Please use /login or /register before playing.");
        } else if (current.authenticated) {
            player.sendMessage("Authentication session restored.");
        }
        PreJoinSubmission pending = current.preJoinSubmission;
        current.preJoinSubmission = null;
        if (pending == null) {
            showAuthenticationDialog(player, current);
        } else if (!current.authenticated) {
            switch (pending.kind()) {
                case LOGIN -> login(player, pending.first());
                case REGISTER -> register(player, pending.first(), pending.second());
                case RECOVERY -> recoverEmail(player, pending.first());
            }
        }
        scheduleTimeout(player, current);
        scheduleAuthenticationReminders(player, current);
    }

    public void onQuit(Player player) {
        UUID uuid = player.getUniqueId();
        Session session = sessions.get(uuid);
        if (session == null || session.player != player) {
            clearPreJoin(uuid);
            return;
        }
        closeAuthenticationDialog(player);
        Location quitLocation = player.getLocation() == null ? null : player.getLocation().clone();
        double quitX = quitLocation == null ? 0.0 : quitLocation.getX();
        double quitY = quitLocation == null ? 64.0 : quitLocation.getY();
        double quitZ = quitLocation == null ? 0.0 : quitLocation.getZ();
        float quitYaw = quitLocation == null ? 0.0f : quitLocation.getYaw();
        float quitPitch = quitLocation == null ? 0.0f : quitLocation.getPitch();
        String quitWorld = quitLocation == null || quitLocation.getWorld() == null
            ? "world" : quitLocation.getWorld().getName();
        String playerName = player.getName();
        String playerIp = session.ip;
        String playerCountry = country(player);
        boolean saveQuitLocation = config().saveQuitLocation();
        if (session.authenticated) runLogoutCommandsAfterQuit(playerName, playerIp, playerCountry);
        restoreLimbo(player, session);
        sessions.remove(uuid, session);
        busy.remove(uuid);
        releaseJoinAddress(session.ip);
        scheduler.runAsync(() -> service.disconnectIfConnection(playerName, session.connectionToken,
            quitX, quitY, quitZ, quitYaw, quitPitch, quitWorld, saveQuitLocation));
    }

    /** Runs console onLogout hooks; player-executor hooks cannot be replayed after disconnect. */
    private void runLogoutCommandsAfterQuit(String playerName, String playerIp, String playerCountry) {
        for (EventCommands.ConfiguredCommand command : eventCommands.get("onLogout")) {
            if (command.accountsAtLeast() >= 0 || command.accountsLessThan() >= 0
                || command.executor() != EventCommands.Executor.CONSOLE) continue;
            Runnable execute = () -> {
                String text = command.command()
                    .replace("%p", playerName.toLowerCase(java.util.Locale.ROOT))
                    .replace("%nick", playerName)
                    .replace("%ip", playerIp)
                    .replace("%country", playerCountry);
                if (text.startsWith("/")) text = text.substring(1);
                if (!text.isBlank()) plugin.getServer().dispatchCommand(
                    plugin.getServer().getConsoleSender(), text);
            };
            if (command.delayTicks() <= 0) scheduler.runGlobal(execute);
            else scheduler.runDelayedGlobal(execute, command.delayTicks());
        }
    }

    public void login(Player player, String password) {
        closeAuthenticationDialog(player);
        if (!begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        String playerIp = address(player);
        boolean sessionEnabled = config().sessionEnabled();
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.loginIfConnection(
                playerName, password, playerIp, sessionEnabled, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                Session session = sessions.get(player.getUniqueId());
                if (session == null || !player.isOnline()) return;
                if (result == PlatformAuthService.AccountResult.SUCCESS) {
                    completeAuthentication(player, session, false);
                    player.sendMessage("Login successful.");
                    runEventCommands("onLogin", player, session);
                    if (session.firstLogin) runEventCommands("onFirstLogin", player, session);
                } else if (result == PlatformAuthService.AccountResult.TOTP_REQUIRED) {
                    session.totpPending = true;
                    player.sendMessage("Two-factor authentication is required. Use /2fa <code>.");
                    showAuthenticationDialog(player, session);
                } else if (result == PlatformAuthService.AccountResult.CAPTCHA_REQUIRED) {
                    String challenge = service.captchaChallenge(playerName, playerIp);
                    player.sendMessage("A CAPTCHA is required. Use /captcha " + challenge + ".");
                    showAuthenticationDialog(player, session);
                } else {
                    player.sendMessage(loginMessage(result));
                    if (result == PlatformAuthService.AccountResult.WRONG_PASSWORD
                        && config().kickOnWrongPassword()) {
                        player.kickPlayer("Wrong password.");
                    } else showAuthenticationDialog(player, session);
                }
            });
        });
    }

    public void register(Player player, String password, String confirmation) {
        closeAuthenticationDialog(player);
        if (!begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        String playerIp = address(player);
        boolean allowMultipleAccounts = player.hasPermission("authme.allowmultipleaccounts");
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.registerIfConnection(
                playerName, password, confirmation, playerIp, connectionToken, allowMultipleAccounts);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                Session session = sessions.get(player.getUniqueId());
                if (session == null || !player.isOnline()) return;
                if (result == PlatformAuthService.AccountResult.SUCCESS) {
                    session.registered = true;
                    session.firstLogin = true;
                    switchPermissionGroup(player, session);
                    prepareLimbo(player, session);
                    runEventCommands("onRegister", player, session);
                    if (config().forceKickAfterRegister()) {
                        player.sendMessage("Registration successful.");
                        long delayTicks = Math.max(0L, config().registrationKickDelaySeconds()) * 20L;
                        scheduler.runDelayedForPlayer(player,
                            () -> { if (player.isOnline()) player.kickPlayer("Registration complete."); },
                            delayTicks);
                    } else if (config().forceLoginAfterRegister()) {
                        player.sendMessage("Registration successful. Please use /login.");
                    } else if (config().registrationType()
                        == io.github.authme.fabric.config.RegistrationType.EMAIL) {
                        player.sendMessage("Registration successful. Check your email for the generated password.");
                    } else {
                        player.sendMessage("Registration successful.");
                        session.portalAfterRegister = config().forcePortalAfterRegister();
                        login(player, password);
                    }
                } else if (result == PlatformAuthService.AccountResult.CAPTCHA_REQUIRED) {
                    player.sendMessage("A CAPTCHA is required. Use /captcha "
                        + service.captchaChallenge(playerName, playerIp) + ".");
                    showAuthenticationDialog(player, session);
                } else {
                    player.sendMessage(registrationMessage(result));
                    showAuthenticationDialog(player, session);
                }
            });
        });
    }

    public void captcha(Player player, String code) {
        if (!begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        String playerIp = address(player);
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.verifyCaptchaIfConnection(
                playerName, playerIp, code, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                if (!player.isOnline()) return;
                player.sendMessage(result == PlatformAuthService.AccountResult.SUCCESS
                    ? "CAPTCHA accepted; you may now log in."
                    : "The CAPTCHA code is invalid or expired.");
            });
        });
    }

    public void addEmail(Player player, String email, String confirmation) {
        if (!isAuthenticated(player) || !begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.addEmailIfConnection(
                playerName, email, confirmation, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                if (player.isOnline()) player.sendMessage(emailMessage(result));
            });
        });
    }

    public void changeEmail(Player player, String oldEmail, String newEmail) {
        if (!isAuthenticated(player) || !begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.changeEmailIfConnection(
                playerName, oldEmail, newEmail, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                if (player.isOnline()) player.sendMessage(emailMessage(result));
            });
        });
    }

    public void recoverEmail(Player player, String email) {
        if (!begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        String playerIp = address(player);
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.requestEmailRecoveryIfConnection(
                playerName, email, playerIp, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                if (player.isOnline()) player.sendMessage(emailMessage(result));
            });
        });
    }

    public void confirmEmail(Player player, String code) {
        if (!begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.confirmEmailIfConnection(
                playerName, code, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                if (player.isOnline()) player.sendMessage(emailMessage(result));
            });
        });
    }

    public void setRecoveredPassword(Player player, String password) {
        if (!begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.setRecoveredPasswordIfConnection(
                playerName, password, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                if (player.isOnline()) player.sendMessage(result == PlatformAuthService.AccountResult.SUCCESS
                    ? "Recovery password changed; please log in again." : emailMessage(result));
            });
        });
    }

    public void showEmail(Player player) {
        if (!isAuthenticated(player)) return;
        String playerName = player.getName();
        scheduler.runAsync(() -> {
            String email = service.email(playerName);
            scheduler.runForPlayer(player, () -> {
                if (player.isOnline()) player.sendMessage("Registered email: " + maskEmail(email));
            });
        });
    }

    public void enablePremium(Player player) {
        if (!isAuthenticated(player) || !begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        UUID playerId = player.getUniqueId();
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.enablePremiumIfConnection(
                playerName, playerId, onlineMode, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                if (player.isOnline()) player.sendMessage(result == PlatformAuthService.AccountResult.SUCCESS
                    ? "Premium mode enabled." : premiumMessage(result));
            });
        });
    }

    public void disablePremium(Player player) {
        if (!isAuthenticated(player) || !begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.disablePremiumIfConnection(
                playerName, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                if (player.isOnline()) player.sendMessage(result == PlatformAuthService.AccountResult.SUCCESS
                    ? "Premium mode disabled." : premiumMessage(result));
            });
        });
    }

    public void adminRegister(CommandSender sender, String target, String password) {
        scheduler.runAsync(() -> sendAdminResult(sender, "register",
            service.adminRegister(target, password), target));
    }

    public void adminUnregister(CommandSender sender, String target) {
        scheduler.runAsync(() -> sendAdminResult(sender, "unregister",
            service.adminUnregister(target), target));
    }

    public void adminSetPassword(CommandSender sender, String target, String password) {
        scheduler.runAsync(() -> sendAdminResult(sender, "password",
            service.adminSetPassword(target, password), target));
    }

    public void adminAuth(CommandSender sender, String target, boolean authenticated) {
        scheduler.runAsync(() -> sendAdminResult(sender, authenticated ? "auth" : "unauth",
            authenticated ? service.adminAuth(target) : service.adminUnauth(target), target));
    }

    public void adminAccountData(CommandSender sender, String target) {
        scheduler.runAsync(() -> {
            DataSource.LookupResult result = service.lookup(target);
            if (!result.successful()) {
                sendCommandResult(sender, "AuthMe database unavailable.");
            } else if (result.auth() == null) {
                sendCommandResult(sender, "Account not found: " + target);
            } else {
                io.github.authme.fabric.datasource.PlayerAuth account = result.auth();
                sendCommandResult(sender, "Account " + account.getName() + ": registered="
                    + (account.getRegistrationDate() > 0) + ", logged=" + account.isLogged()
                    + ", session=" + account.hasSession() + ", email=" + maskEmail(account.getEmail())
                    + ", premium=" + (account.getPremiumUuid() != null));
            }
        });
    }

    public void adminIp(CommandSender sender, String target) {
        scheduler.runAsync(() -> {
            DataSource.LookupResult result = service.lookup(target);
            if (!result.successful()) sendCommandResult(sender, "AuthMe database unavailable.");
            else if (result.auth() == null) sendCommandResult(sender, "Account not found: " + target);
            else sendCommandResult(sender, "Last IP for " + target + ": "
                + (result.auth().getLastIp() == null ? "unknown" : result.auth().getLastIp()));
        });
    }

    public void adminAccounts(CommandSender sender, String target) {
        scheduler.runAsync(() -> {
            DataSource.LookupResult account = service.lookup(target);
            if (!account.successful() || account.auth() == null) {
                sendCommandResult(sender, account.successful() ? "Account not found: " + target
                    : "AuthMe database unavailable.");
                return;
            }
            String ip = account.auth().getLastIp();
            if (ip == null || ip.isBlank()) {
                sendCommandResult(sender, "No last IP is stored for " + target + ".");
                return;
            }
            DataSource.QueryResult<java.util.List<String>> result = service.accountsByIp(ip);
            sendCommandResult(sender, result.successful()
                ? "Accounts registered from the same IP: " + String.join(", ", result.value())
                : "AuthMe database unavailable.");
        });
    }

    public void playerAccounts(Player player) {
        if (!isAuthenticated(player)) {
            player.sendMessage("You must be authenticated to view associated accounts.");
            return;
        }
        String playerName = player.getName();
        scheduler.runAsync(() -> {
            DataSource.LookupResult account = service.lookup(playerName);
            if (!account.successful() || account.auth() == null) {
                sendCommandResult(player, account.successful() ? "Account not found." : "AuthMe database unavailable.");
                return;
            }
            String ip = account.auth().getLastIp();
            if (ip == null || ip.isBlank()) {
                sendCommandResult(player, "No last IP is stored for your account.");
                return;
            }
            DataSource.QueryResult<java.util.List<String>> result = service.accountsByIp(ip);
            if (!result.successful()) {
                sendCommandResult(player, "AuthMe database unavailable.");
            } else {
                sendCommandResult(player, "Accounts associated with your last IP: "
                    + String.join(", ", result.value()));
            }
        });
    }

    public void adminRecent(CommandSender sender, int limit) {
        scheduler.runAsync(() -> {
            DataSource.QueryResult<java.util.List<io.github.authme.fabric.datasource.PlayerAuth>> result =
                service.recentAccounts(limit);
            if (!result.successful()) {
                sendCommandResult(sender, "AuthMe database unavailable.");
                return;
            }
            java.util.List<String> names = new java.util.ArrayList<>();
            for (io.github.authme.fabric.datasource.PlayerAuth auth : result.value()) names.add(auth.getName());
            sendCommandResult(sender, "Recent accounts: " + String.join(", ", names));
        });
    }

    public void adminPurge(CommandSender sender, int days) {
        collectPurgeBypassNames(bypassNames ->
            scheduler.runAsync(() -> {
                long cutoff = System.currentTimeMillis() - Math.max(1, days) * 86_400_000L;
                PurgeOutcome result = purgeAccounts(cutoff, 1000, bypassNames);
                sendCommandResult(sender, result.successful
                    ? "Purged " + result.accounts + " account(s) and cleaned " + result.files + " optional file(s)."
                    : "AuthMe purge failed.");
            }));
    }

    public void adminResetPosition(CommandSender sender, String target) {
        scheduler.runAsync(() -> {
            if ("*".equals(target)) {
                DataSource.OperationResult result = service.resetAllPositions();
                sendCommandResult(sender, result.successful()
                    ? "All stored AuthMe locations were reset."
                    : "AuthMe location reset failed.");
                return;
            }
            PlatformAuthService.AccountResult result = service.resetPosition(target);
            sendCommandResult(sender, result == PlatformAuthService.AccountResult.SUCCESS
                ? "Stored location reset for " + target + "."
                : result == PlatformAuthService.AccountResult.NOT_REGISTERED
                    ? "Account not found: " + target : "AuthMe location reset failed.");
        });
    }

    public void adminPurgePlayer(CommandSender sender, String target, boolean force) {
        scheduler.runAsync(() -> {
            DataSource.LookupResult account = service.lookup(target);
            PlatformAuthService.AccountResult result;
            int files = 0;
            if (!account.successful()) result = PlatformAuthService.AccountResult.DATABASE_ERROR;
            else if (account.auth() == null) result = PlatformAuthService.AccountResult.NOT_REGISTERED;
            else {
                result = service.purgePlayer(target, force);
                if (result == PlatformAuthService.AccountResult.SUCCESS) {
                    files = io.github.authme.fabric.util.PurgeFileCleaner.clean(serverRoot(), config(),
                        List.of(account.auth()), onlineMode);
                }
            }
            String message = switch (result) {
                case SUCCESS -> "Account purged: " + target + " and cleaned " + files + " optional file(s).";
                case PURGE_CONFIRMATION_REQUIRED -> "Repeat with /authme purgeplayer " + target + " force.";
                case NOT_REGISTERED -> "Account not found: " + target;
                default -> "AuthMe player purge failed.";
            };
            sendCommandResult(sender, message);
        });
    }

    public void adminPurgeBannedPlayers(CommandSender sender) {
        collectPurgeBypassNames(bypass -> scheduler.runGlobal(() -> {
            java.util.List<String> banned = new java.util.ArrayList<>();
            for (org.bukkit.OfflinePlayer offline : plugin.getServer().getBannedPlayers()) {
                String name = offline.getName();
                if (name != null && name.matches("[A-Za-z0-9_-]{1,16}") && banned.size() < 10_000) {
                    banned.add(name.toLowerCase(java.util.Locale.ROOT));
                }
            }
            scheduler.runAsync(() -> {
                int removed = 0;
                List<io.github.authme.fabric.datasource.PlayerAuth> removedAccounts = new ArrayList<>();
                for (String name : banned) {
                    if (bypass.contains(name)) continue;
                    DataSource.LookupResult account = service.lookup(name);
                    if (account.successful() && account.auth() != null
                        && service.purgePlayer(name, true) == PlatformAuthService.AccountResult.SUCCESS) {
                        removed++;
                        removedAccounts.add(account.auth());
                    }
                }
                int files = io.github.authme.fabric.util.PurgeFileCleaner.clean(serverRoot(), config(),
                    removedAccounts, onlineMode);
                sendCommandResult(sender, "Purged " + removed + " banned AuthMe account(s) and cleaned "
                    + files + " optional file(s).");
            });
        }));
    }

    public void adminSwitchAntiBot(CommandSender sender, Boolean enabled) {
        AntiBotManager gate = antiBot;
        boolean active;
        if (enabled == null) active = gate.toggle();
        else {
            gate.setEnabled(enabled);
            active = gate.isEnabled();
        }
        sendCommandResult(sender, "AuthMe AntiBot is now " + (active ? "enabled" : "disabled") + ".");
    }

    public void adminSetSpawn(CommandSender sender, boolean first) {
        if (!(sender instanceof Player player)) {
            sendCommandResult(sender, "This command must be run by a player.");
            return;
        }
        Location location = player.getLocation();
        SpawnLocation stored = new SpawnLocation(player.getWorld().getKey().toString(), location.getX(),
            location.getY(), location.getZ(), location.getYaw(), location.getPitch());
        sendCommandResult(sender, spawnStore.set(first ? "firstspawn" : "spawn", stored)
            ? "AuthMe " + (first ? "first" : "main") + " spawn saved."
            : "AuthMe spawn could not be saved.");
    }

    public void adminSpawn(CommandSender sender, boolean first) {
        if (!(sender instanceof Player player)) {
            sendCommandResult(sender, "This command must be run by a player.");
            return;
        }
        SpawnLocation stored = spawnStore.get(first ? "firstspawn" : "spawn");
        if (stored == null) {
            player.sendMessage("AuthMe " + (first ? "first" : "main") + " spawn is not configured.");
            return;
        }
        scheduler.runForPlayer(player, () -> {
            org.bukkit.World world = resolveWorld(stored.world());
            if (world == null) {
                player.sendMessage("AuthMe spawn world is not loaded: " + stored.world());
                return;
            }
            player.teleport(new Location(world, stored.x(), stored.y(), stored.z(), stored.yaw(), stored.pitch()));
            player.sendMessage("Teleported to AuthMe " + (first ? "first" : "main") + " spawn.");
        });
    }

    private org.bukkit.World resolveWorld(String key) {
        org.bukkit.World direct = plugin.getServer().getWorld(key);
        if (direct != null) return direct;
        for (org.bukkit.World world : plugin.getServer().getWorlds()) {
            if (world.getKey().toString().equalsIgnoreCase(key)
                || world.getName().equalsIgnoreCase(key)) return world;
        }
        return null;
    }

    public void adminBackup(CommandSender sender) {
        scheduler.runAsync(() -> {
            sendCommandResult(sender, backupNow()
                ? "AuthMe backup created."
                : "AuthMe backup failed.");
        });
    }

    /** Runs an administrator-authorized AuthMe data converter off the server thread. */
    public void adminConverterList(CommandSender sender) {
        sendCommandResult(sender, org.bukkit.ChatColor.translateAlternateColorCodes('&',
            io.github.authme.fabric.converter.Converters.listing()));
    }

    public void adminConverter(CommandSender sender, String id, String argument) {
        if (id == null || id.isBlank() || !id.matches("[A-Za-z0-9_-]{1,32}")) {
            sendCommandResult(sender, "Invalid converter id.");
            return;
        }
        scheduler.runAsync(() -> {
            io.github.authme.fabric.converter.Converter converter =
                io.github.authme.fabric.converter.Converters.build(id, argument);
            if (converter == null) {
                sendCommandResult(sender, "Unknown converter: " + id + ". Use /authme converter list.");
                return;
            }
            try {
                io.github.authme.fabric.converter.Converter.Result result = converter.convert(service.dataSource());
                String note = result.getNote().isBlank() ? "" : " (" + result.getNote() + ")";
                sendCommandResult(sender, "Imported " + result.getImported() + ", skipped "
                    + result.getSkipped() + note + ".");
            } catch (Exception exception) {
                plugin.getLogger().warning("AuthMe converter " + id + " failed: " + exception.getMessage());
                sendCommandResult(sender, "AuthMe converter failed.");
            }
        });
    }

    public void adminMessages(CommandSender sender) {
        scheduler.runAsync(() -> {
            io.github.authme.fabric.config.Messages messages =
                new io.github.authme.fabric.config.Messages(config().configDir(), config().messagesLanguage());
            if (!messages.load()) {
                sendCommandResult(sender, "AuthMe messages.yml could not be loaded.");
                return;
            }
            int added = messages.addMissingDefaults();
            sendCommandResult(sender, added < 0
                ? "AuthMe messages.yml could not be updated."
                : "AuthMe added " + added + " missing message(s).");
        });
    }

    public void adminEmail(CommandSender sender, String target, String email) {
        scheduler.runAsync(() -> {
            if (email == null) {
                DataSource.LookupResult lookup = service.lookup(target);
                if (!lookup.successful()) sendCommandResult(sender, "AuthMe database unavailable.");
                else if (lookup.auth() == null) sendCommandResult(sender, "Account not found: " + target);
                else sendCommandResult(sender, "Email for " + target + ": "
                    + maskEmail(lookup.auth().getEmail()));
            } else {
                sendAdminResult(sender, "email", service.adminSetEmail(target, email), target);
            }
        });
    }

    public void adminTotp(CommandSender sender, String target, boolean disable) {
        scheduler.runAsync(() -> {
            if (!disable) {
                DataSource.LookupResult lookup = service.lookup(target);
                sendCommandResult(sender, lookup.successful() && lookup.auth() != null
                    ? "TOTP enabled: " + (io.github.authme.fabric.totp.TotpProvider.isPlausibleSecret(lookup.auth().getTotpKey()))
                    : "Account not found: " + target);
            } else {
                sendAdminResult(sender, "totp", service.adminDisableTotp(target), target);
            }
        });
    }

    public void adminPremium(CommandSender sender, String target, boolean enabled) {
        java.util.UUID uuid = null;
        if (enabled) {
            Player online = plugin.getServer().getPlayerExact(target);
            if (online != null) uuid = online.getUniqueId();
        }
        java.util.UUID premiumUuid = uuid;
        scheduler.runAsync(() -> sendAdminResult(sender, "premium",
            enabled && premiumUuid == null ? PlatformAuthService.AccountResult.PREMIUM_UNAVAILABLE
                : service.adminSetPremium(target, enabled ? premiumUuid : null), target));
    }

    /**
     * Implements the non-mutating AuthMe debug children that are safe to expose from a
     * platform adapter. Database contents, passwords and SMTP credentials are never printed.
     */
    public void adminDebug(CommandSender sender, String child, String first, String second) {
        String operation = child == null ? "" : child.trim().toLowerCase(java.util.Locale.ROOT);
        switch (operation) {
            case "db", "stats" -> scheduler.runAsync(() -> {
                int count = service.dataSource().countAuths();
                sendCommandResult(sender, "AuthMe database=" + service.dataSource().getType()
                    + ", accounts=" + Math.max(0, count));
            });
            case "country" -> {
                String address = first;
                if ((address == null || address.isBlank()) && sender instanceof Player player) address = address(player);
                String value = address == null || address.isBlank() ? "--" : geoIp.countryCode(address);
                sendCommandResult(sender, "AuthMe country=" + value);
            }
            case "spawn" -> {
                SpawnLocation spawn = spawnStore.get(first == null || first.isBlank() ? "spawn" : first);
                sendCommandResult(sender, spawn == null ? "AuthMe spawn is not configured."
                    : "AuthMe spawn=" + spawn.world() + " " + spawn.x() + "," + spawn.y() + "," + spawn.z());
            }
            case "limbo" -> {
                if (sender instanceof Player player) {
                    Session session = sessions.get(player.getUniqueId());
                    sendCommandResult(sender, session == null ? "No AuthMe session is active."
                        : "AuthMe session registered=" + session.registered + ", authenticated=" + session.authenticated);
                } else sendCommandResult(sender, "The limbo debug view requires a player sender.");
            }
            case "perm" -> {
                String node = first == null ? "" : first.trim();
                if (node.length() > 256 || !node.matches("[A-Za-z0-9_.:*?-]+")) {
                    sendCommandResult(sender, "Invalid permission node.");
                } else sendCommandResult(sender, "Permission " + node + "=" + sender.hasPermission(node));
            }
            case "valid" -> sendCommandResult(sender, "usernameValid=" + service.isValidUsername(first)
                + ", passwordValid=" + service.isValidPasswordInput(second));
            case "mail" -> sendCommandResult(sender,
                "Debug mail sending is disabled; configure SMTP and use a real recovery/verification flow.");
            case "mysqldef" -> {
                io.github.authme.fabric.datasource.DataSource.MySqlDefinitionOperation mysqlOperation =
                    mysqlDefinitionOperation(first);
                if (mysqlOperation == null
                    || (mysqlOperation != io.github.authme.fabric.datasource.DataSource.MySqlDefinitionOperation.DETAILS
                        && (second == null || second.isBlank()))) {
                    sendCommandResult(sender, "Usage: /authme debug mysqldef add|remove <LASTLOGIN|LASTIP|EMAIL>");
                    sendCommandResult(sender, "       /authme debug mysqldef details");
                } else {
                    scheduler.runAsync(() -> {
                        io.github.authme.fabric.datasource.DataSource.MySqlDefinitionResult result =
                            service.mysqlDefinition(mysqlOperation, second);
                        if (!result.supported() || !result.successful()) {
                            sendCommandResult(sender, result.error());
                        } else {
                            for (String line : result.lines()) sendCommandResult(sender, line);
                        }
                    });
                }
            }
            default -> sendCommandResult(sender,
                "Usage: /authme debug db|stats|country [address]|spawn [firstspawn]|limbo|perm <node>|valid <name> <password>|mail|mysqldef ...");
        }
    }

    private static io.github.authme.fabric.datasource.DataSource.MySqlDefinitionOperation mysqlDefinitionOperation(
        String value) {
        if (value == null) return null;
        try {
            return io.github.authme.fabric.datasource.DataSource.MySqlDefinitionOperation.valueOf(
                value.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    private void sendAdminResult(CommandSender sender, String operation,
                                 PlatformAuthService.AccountResult result, String target) {
        sendCommandResult(sender, adminMessage(operation, result, target));
    }

    private static String adminMessage(String operation, PlatformAuthService.AccountResult result, String target) {
        if (result == PlatformAuthService.AccountResult.SUCCESS) return operation + " completed for " + target + ".";
        return switch (result) {
            case NOT_REGISTERED -> "Account not found: " + target;
            case ALREADY_REGISTERED -> "Account already exists: " + target;
            case INVALID_INPUT, PASSWORD_MISMATCH, UNSAFE_PASSWORD -> "Invalid or unsafe input.";
            case PREMIUM_UNAVAILABLE -> "Premium identity is unavailable for this target.";
            case LOGIN_LIMIT -> "The per-IP login limit has been reached.";
            case EMAIL_INVALID -> "The email address is invalid or not allowed.";
            default -> "AuthMe operation failed for " + target + ".";
        };
    }

    public void logout(Player player) {
        closeAuthenticationDialog(player);
        if (!begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.logoutIfConnection(
                playerName, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                Session session = sessions.get(player.getUniqueId());
                if (session == null || !player.isOnline()) return;
                if (result == PlatformAuthService.AccountResult.SUCCESS) {
                    session.authenticated = false;
                    session.totpPending = false;
                    prepareLimbo(player, session);
                    player.sendMessage("You have been logged out.");
                    runEventCommands("onLogout", player, session);
                    showAuthenticationDialog(player, session);
                } else player.sendMessage("Could not log out because the account database is unavailable.");
            });
        });
    }

    public void unregister(Player player, String password) {
        closeAuthenticationDialog(player);
        if (!begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.unregisterIfConnection(
                playerName, password, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                Session session = sessions.get(player.getUniqueId());
                if (session == null || !player.isOnline()) return;
                if (result == PlatformAuthService.AccountResult.SUCCESS) {
                    session.authenticated = false;
                    session.registered = false;
                    session.totpPending = false;
                    prepareLimbo(player, session);
                    player.sendMessage("Your account has been unregistered.");
                    runEventCommands("onUnregister", player, session);
                    showAuthenticationDialog(player, session);
                } else player.sendMessage(loginMessage(result));
            });
        });
    }

    public void changePassword(Player player, String oldPassword, String newPassword) {
        if (!begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.changePasswordIfConnection(
                playerName, oldPassword, newPassword, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                if (player.isOnline()) player.sendMessage(result == PlatformAuthService.AccountResult.SUCCESS
                    ? "Password changed successfully." : loginMessage(result));
            });
        });
    }

    public void verifyTotp(Player player, String code) {
        closeAuthenticationDialog(player);
        Session session = sessions.get(player.getUniqueId());
        if (session == null || !session.totpPending) {
            player.sendMessage("A password login requiring two-factor authentication is not pending.");
            return;
        }
        if (!begin(player)) return;
        String playerName = player.getName();
        String playerIp = address(player);
        boolean sessionEnabled = config().sessionEnabled();
        UUID playerId = player.getUniqueId();
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.verifyTotpIfConnection(
                playerName, code, playerIp, sessionEnabled, session.connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                Session current = sessions.get(playerId);
                if (current == null || !player.isOnline()) return;
                if (result == PlatformAuthService.AccountResult.SUCCESS) {
                    completeAuthentication(player, current, false);
                    player.sendMessage("Two-factor authentication successful.");
                    runEventCommands("onLogin", player, current);
                    if (current.firstLogin) runEventCommands("onFirstLogin", player, current);
                } else {
                    player.sendMessage(totpMessage(result));
                    showAuthenticationDialog(player, current);
                }
            });
        });
    }

    public void enableTotp(Player player) {
        if (!isAuthenticated(player) || !begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        scheduler.runAsync(() -> {
            PlatformAuthService.TotpResult result = service.enableTotpIfConnection(
                playerName, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                if (!player.isOnline()) return;
                if (result.result() == PlatformAuthService.AccountResult.SUCCESS) {
                    Session current = sessions.get(player.getUniqueId());
                    if (current != null) current.pendingTotpSetupKey = result.secret();
                    player.sendMessage("Two-factor secret: " + result.secret());
                    player.sendMessage("Store this secret safely, then use /2fa confirm <code> to verify it.");
                } else player.sendMessage(totpMessage(result.result()));
            });
        });
    }

    public void confirmTotp(Player player, String code) {
        if (!isAuthenticated(player) || !begin(player)) return;
        Session session = sessions.get(player.getUniqueId());
        String secret = session == null ? "" : session.pendingTotpSetupKey;
        if (secret.isBlank()) {
            finish(player);
            player.sendMessage("Start two-factor setup with /2fa enable first.");
            return;
        }
        String playerName = player.getName();
        long connectionToken = session.connectionToken;
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.confirmTotpIfConnection(
                playerName, secret, code, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                Session current = sessions.get(player.getUniqueId());
                if (current == null || !player.isOnline()) return;
                if (result == PlatformAuthService.AccountResult.SUCCESS) {
                    current.pendingTotpSetupKey = "";
                    player.sendMessage("Two-factor authentication enabled.");
                } else player.sendMessage(totpMessage(result));
            });
        });
    }

    public void disableTotp(Player player, String code) {
        if (!isAuthenticated(player) || !begin(player)) return;
        Session operationSession = sessions.get(player.getUniqueId());
        long connectionToken = operationSession == null ? 0L : operationSession.connectionToken;
        String playerName = player.getName();
        scheduler.runAsync(() -> {
            PlatformAuthService.AccountResult result = service.disableTotpIfConnection(
                playerName, code, connectionToken);
            scheduler.runForPlayer(player, () -> {
                finish(player);
                if (player.isOnline()) player.sendMessage(result == PlatformAuthService.AccountResult.SUCCESS
                    ? "Two-factor authentication disabled." : totpMessage(result));
            });
        });
    }

    private void prepareLimbo(Player player, Session session) {
        if (player == null || session == null || isUnrestricted(player)) return;
        applyPermissionGroup(player, session);
        if (!config().restrictUnauthenticated()) return;
        if (!session.limboApplied) {
            LimboStateStore.State saved = limboStore.load(session.uuid);
            session.limboState = saved == null
                ? new LimboStateStore.State(player.isOp(), player.getAllowFlight(), player.isFlying(),
                    player.getWalkSpeed(), player.getFlySpeed(), player.isInvulnerable())
                : saved;
            if (saved == null && !limboStore.save(session.uuid, session.limboState)) {
                plugin.getLogger().warning("Could not persist AuthMe limbo state for " + player.getName());
            }
            session.limboApplied = true;
        }
        if (config().permissionCheckEnabled()) player.setOp(false);
        if (!"NOTHING".equalsIgnoreCase(config().limboRestoreAllowFlight())) {
            player.setAllowFlight(false);
            player.setFlying(false);
        }
        if (config().removeSpeed()) {
            player.setWalkSpeed(0.0f);
            player.setFlySpeed(0.0f);
        }
        if (config().applyBlindEffect()) {
            player.addPotionEffect(new PotionEffect(PotionEffectType.BLINDNESS, Integer.MAX_VALUE, 0, false, false, false));
            session.blindApplied = true;
        }
        if (config().forceSurvivalMode() && !config().forceSurvivalOnlyAfterLogin()
            && !player.hasPermission("authme.bypassforcesurvival")) {
            player.setGameMode(GameMode.SURVIVAL);
        }
        if (config().hideTablist()) hideFromTablist(player);
        if (config().teleportUnauthenticatedToSpawn() && !config().noTeleport()) {
            session.teleportedToSpawn = teleportToStoredSpawn(player, "spawn");
        }
    }

    private void restoreLimbo(Player player, Session session) {
        if (player == null || session == null) return;
        restorePermissionGroup(player, session);
        if (!session.limboApplied) return;
        LimboStateStore.State state = session.limboState;
        if (state != null) {
            if (config().permissionCheckEnabled()) player.setOp(state.operator());
            restoreFlight(player, state);
            restoreSpeed(player, state);
            player.setInvulnerable(state.invulnerable());
        }
        if (session.blindApplied) player.removePotionEffect(PotionEffectType.BLINDNESS);
        if (session.teleportedToSpawn && session.joinLocation != null && !config().noTeleport()
            && player.isOnline()) {
            player.teleport(session.joinLocation);
        }
        session.teleportedToSpawn = false;
        session.limboApplied = false;
        limboStore.remove(session.uuid);
        showInTablist(player);
    }

    private void applyPermissionGroup(Player player, Session session) {
        if (!config().groupOptionsEnabled() || !session.accountResolved || session.groupSnapshot != null) return;
        String group = session.registered ? config().registeredPlayerGroup() : config().unregisteredPlayerGroup();
        if (group.isBlank()) return;
        session.groupSnapshot = PermissionBridge.applyGroup(session.uuid, group);
        if (PermissionBridge.providerPresent() && !session.groupSnapshot.applied()) {
            plugin.getLogger().warning("Could not switch " + player.getName()
                + " to AuthMe group '" + group + "'.");
        }
    }

    private void switchPermissionGroup(Player player, Session session) {
        restorePermissionGroup(player, session);
        applyPermissionGroup(player, session);
    }

    private void restorePermissionGroup(Player player, Session session) {
        if (session.groupSnapshot == null) return;
        if (!PermissionBridge.restoreGroup(session.uuid, session.groupSnapshot)) {
            plugin.getLogger().warning("Could not restore the permission group for " + player.getName() + ".");
        }
        session.groupSnapshot = null;
    }

    private void restoreFlight(Player player, LimboStateStore.State state) {
        String mode = config().limboRestoreAllowFlight().toUpperCase(java.util.Locale.ROOT);
        if ("NOTHING".equals(mode)) return;
        boolean allow = switch (mode) {
            case "ENABLE" -> true;
            case "DISABLE" -> false;
            default -> state.mayFly();
        };
        player.setAllowFlight(allow);
        player.setFlying(allow && state.flying());
    }

    private void restoreSpeed(Player player, LimboStateStore.State state) {
        String walkMode = config().limboRestoreWalkSpeed().toUpperCase(java.util.Locale.ROOT);
        String flyMode = config().limboRestoreFlySpeed().toUpperCase(java.util.Locale.ROOT);
        if (!"NOTHING".equals(walkMode)) {
            float value = state.walkingSpeed();
            if ("RESTORE_NO_ZERO".equals(walkMode) && value <= 0.0f) value = 0.1f;
            player.setWalkSpeed(clampSpeed(value, 0.1f));
        }
        if (!"NOTHING".equals(flyMode)) {
            float value = state.flyingSpeed();
            if ("RESTORE_NO_ZERO".equals(flyMode) && value <= 0.0f) value = 0.05f;
            player.setFlySpeed(clampSpeed(value, 0.05f));
        }
    }

    private static float clampSpeed(float value, float fallback) {
        return Float.isFinite(value) ? Math.max(-1.0f, Math.min(1.0f, value)) : fallback;
    }

    private void completeAuthentication(Player player, Session session, boolean sessionLogin) {
        if (sessions.get(player.getUniqueId()) != session || !player.isOnline()) return;
        closeAuthenticationDialog(player);
        displaceOtherSessions(player, session);
        session.totpPending = false;
        restoreLimbo(player, session);
        if (config().forceSurvivalMode() && config().forceSurvivalOnlyAfterLogin()
            && !player.hasPermission("authme.bypassforcesurvival")) {
            player.setGameMode(GameMode.SURVIVAL);
        }
        if (session.portalAfterRegister && config().forcePortalAfterRegister() && !config().noTeleport()) {
            teleportToFirstSpawn(player);
            session.portalAfterRegister = false;
        } else if (!session.teleportedToSpawn && shouldForceSpawn(player)) {
            teleportToStoredSpawn(player, "spawn");
        }
        showInTablist(player);
        announceDelayedJoin(player, session);
        sendWelcome(player);
        notifyAssociatedAccounts(player);
        scheduleLoginLeaseCheck(player, session);
    }

    private void scheduleLoginLeaseCheck(Player player, Session session) {
        scheduler.runDelayedForPlayer(player, () -> {
            Session current = sessions.get(player.getUniqueId());
            if (current != session || !session.authenticated || !player.isOnline()) return;
            scheduler.runAsync(() -> {
                PlatformAuthService.LoginLeaseStatus status = service.loginLeaseStatus(player.getName());
                scheduler.runForPlayer(player, () -> {
                    Session latest = sessions.get(player.getUniqueId());
                    if (latest != session || !session.authenticated || !player.isOnline()) return;
                    if (status == PlatformAuthService.LoginLeaseStatus.OWNED) {
                        scheduleLoginLeaseCheck(player, session);
                    } else if (status == PlatformAuthService.LoginLeaseStatus.REVOKED
                        && !config().forceSingleSession()) {
                        // Multiple sessions are explicitly allowed. The newest connection owns
                        // the shared per-account lease used for the IP quota.
                    } else {
                        session.authenticated = false;
                        player.kickPlayer(status == PlatformAuthService.LoginLeaseStatus.REVOKED
                            ? "Your AuthMe account was logged in from another location."
                            : "Authentication database unavailable.");
                    }
                });
            });
        }, 100L);
    }

    private void announceDelayedJoin(Player player, Session session) {
        if (!config().delayJoinMessage() || config().removeJoinMessage()
            || session.delayedJoinAnnounced) return;
        session.delayedJoinAnnounced = true;
        String message = config().customJoinMessage();
        if (message.isBlank()) message = "&e" + player.getName() + " joined the game";
        String rendered = message
            .replace("{PLAYER}", player.getName())
            .replace("{DISPLAYNAME}", player.getDisplayName())
            .replace("{DISPLAYNAMENOCOLOR}", org.bukkit.ChatColor.stripColor(player.getDisplayName()));
        String finalMessage = org.bukkit.ChatColor.translateAlternateColorCodes('&', rendered);
        scheduler.runGlobal(() -> plugin.getServer().broadcastMessage(finalMessage));
    }

    private void notifyAssociatedAccounts(Player player) {
        if (!config().displayOtherAccounts()
            || (!player.hasPermission("authme.admin.accounts")
                && !player.hasPermission("authme.admin.seeotheraccounts"))) return;
        String playerName = player.getName();
        scheduler.runAsync(() -> {
            DataSource.LookupResult account = service.lookup(playerName);
            if (!account.successful() || account.auth() == null
                || account.auth().getLastIp() == null || account.auth().getLastIp().isBlank()) return;
            DataSource.QueryResult<List<String>> result = service.accountsByIp(account.auth().getLastIp());
            if (!result.successful() || result.value().size() <= 1
                || (config().otherAccountsThreshold() > 0
                    && result.value().size() < config().otherAccountsThreshold())) return;
            scheduler.runForPlayer(player, () -> {
                Session current = sessions.get(player.getUniqueId());
                if (current != null && current.authenticated && player.isOnline()) {
                    player.sendMessage("Other AuthMe accounts from the same address: "
                        + String.join(", ", result.value()));
                }
            });
            String command = config().otherAccountsCommand().trim();
            if (!command.isBlank() && (config().otherAccountsCommandThreshold() <= 0
                || result.value().size() > config().otherAccountsCommandThreshold())) {
                String rendered = command.replace("%p", playerName.toLowerCase(java.util.Locale.ROOT))
                    .replace("%nick", playerName)
                    .replace("%ip", account.auth().getLastIp());
                if (rendered.startsWith("/")) rendered = rendered.substring(1);
                String dispatch = rendered;
                scheduler.runGlobal(() -> plugin.getServer().dispatchCommand(
                    plugin.getServer().getConsoleSender(), dispatch));
            }
        });
    }

    /**
     * AuthMe's single-session option must invalidate the old in-memory session as well as the
     * database connection generation. Otherwise an old player can continue using the server until
     * their next command even though the account has already been authenticated elsewhere.
     */
    private void displaceOtherSessions(Player player, Session current) {
        List<Session> displaced = new ArrayList<>();
        synchronized (singleSessionLock) {
            if (!config().forceSingleSession()) {
                current.authenticated = true;
            } else {
                for (Session other : sessions.values()) {
                    if (other == current || !other.authenticated || !other.name.equalsIgnoreCase(current.name)) continue;
                    other.authenticated = false;
                    other.totpPending = false;
                    displaced.add(other);
                }
                current.authenticated = true;
            }
        }
        for (Session old : displaced) {
            scheduler.runForPlayer(old.player, () -> {
                Session stillCurrent = sessions.get(old.uuid);
                if (stillCurrent == old && old.player.isOnline()) {
                    old.player.kickPlayer("Your AuthMe account was logged in from another location.");
                }
            });
        }
    }

    private boolean shouldForceSpawn(Player player) {
        if (!config().forceSpawnOnJoin() || config().noTeleport()) return false;
        List<String> worlds = config().forceSpawnWorlds();
        if (worlds.isEmpty()) return true;
        return worlds.stream().filter(value -> value != null)
            .anyMatch(value -> value.equals(player.getWorld().getName())
                || value.equalsIgnoreCase(player.getWorld().getKey().toString()));
    }

    private boolean teleportToStoredSpawn(Player player, String key) {
        SpawnLocation stored = spawnStore.get(key);
        if (stored == null) return false;
        org.bukkit.World world = resolveWorld(stored.world());
        if (world == null) return false;
        return player.teleport(new Location(world, stored.x(), stored.y(), stored.z(), stored.yaw(), stored.pitch()));
    }

    private void teleportToFirstSpawn(Player player) {
        if (teleportToStoredSpawn(player, "firstspawn")) return;
        Location fallback = player.getWorld().getSpawnLocation();
        player.teleport(fallback);
    }

    private void hideFromTablist(Player player) {
        for (Player viewer : plugin.getServer().getOnlinePlayers()) {
            if (viewer != player) scheduler.runForPlayer(viewer, () -> viewer.hidePlayer(plugin, player));
        }
    }

    private void showInTablist(Player player) {
        for (Player viewer : plugin.getServer().getOnlinePlayers()) {
            if (viewer != player) scheduler.runForPlayer(viewer, () -> viewer.showPlayer(plugin, player));
        }
    }

    private void sendWelcome(Player player) {
        if (welcomeLines.isEmpty()) return;
        int logged = 0;
        for (Session value : sessions.values()) if (value.authenticated) logged++;
        String country = country(player);
        for (String line : welcomeLines) {
            String rendered = WelcomeMessage.render(line, player.getName(), address(player),
                plugin.getServer().getOnlinePlayers().size(), plugin.getServer().getMaxPlayers(),
                player.getWorld().getName(), config().serverName(), logged, country);
            rendered = org.bukkit.ChatColor.translateAlternateColorCodes('&', rendered);
            if (config().welcomeBroadcast()) {
                String broadcastMessage = rendered;
                scheduler.runGlobal(() -> plugin.getServer().broadcastMessage(broadcastMessage));
            }
            else player.sendMessage(rendered);
        }
    }

    private boolean reserveJoinAddress(String ip) {
        synchronized (joinedByAddress) {
            int limit = config().maxJoinPerIp();
            if (limit <= 0 || "unknown".equals(ip)) return true;
            AtomicInteger counter = joinedByAddress.get(ip);
            if (counter == null) {
                if (joinedByAddress.size() >= MAX_JOIN_ADDRESS_KEYS) return false;
                counter = new AtomicInteger();
                joinedByAddress.put(ip, counter);
            }
            int next = counter.incrementAndGet();
            if (next <= limit) return true;
            if (counter.decrementAndGet() <= 0) joinedByAddress.remove(ip, counter);
            return false;
        }
    }

    private void releaseJoinAddress(String ip) {
        synchronized (joinedByAddress) {
            if (ip == null || "unknown".equals(ip) || config().maxJoinPerIp() <= 0) return;
            AtomicInteger counter = joinedByAddress.get(ip);
            if (counter != null && counter.decrementAndGet() <= 0) joinedByAddress.remove(ip, counter);
        }
    }

    public boolean isAuthenticated(Player player) {
        Session session = sessions.get(player.getUniqueId());
        return session != null && session.authenticated;
    }

    /** Returns the resolved registration state without performing a database lookup. */
    public boolean isRegistered(Player player) {
        Session session = player == null ? null : sessions.get(player.getUniqueId());
        return session != null && session.registered;
    }

    /** Safe, non-secret status used by the optional PlaceholderAPI expansion. */
    public String placeholderStatus(Player player) {
        if (player == null) return "unknown";
        if (isNpc(player)) return "npc";
        Session session = sessions.get(player.getUniqueId());
        if (session == null || !session.registered) return "unregistered";
        return session.authenticated ? "authenticated" : "login_required";
    }

    /** Bounded online-name view for native Bukkit completion. */
    public List<String> onlinePlayerNames() {
        return plugin.getServer().getOnlinePlayers().stream()
            .map(Player::getName)
            .filter(name -> name != null && !name.isBlank())
            .sorted(String.CASE_INSENSITIVE_ORDER)
            .limit(256)
            .toList();
    }

    public boolean isBlocked(Player player) {
        Session session = sessions.get(player.getUniqueId());
        return !isUnrestricted(player) && config().restrictUnauthenticated()
            && (session == null || !session.authenticated)
            && (session == null || session.registered || config().registrationForce());
    }

    public boolean isUnrestrictedInventory(Player player, String title) {
        return player != null && isBlocked(player)
            && io.github.authme.fabric.auth.UnrestrictedInventoryRegistry.matches(
                title, config().unrestrictedInventories());
    }

    /** Configured integration/NPC names bypass the normal authentication sandbox. */
    public boolean isUnrestricted(Player player) {
        if (player == null) return false;
        if (isNpc(player)) return true;
        String name = player.getName();
        return config().unrestrictedNames().stream().anyMatch(value ->
            value != null && value.trim().equalsIgnoreCase(name));
    }

    /** Citizens/CombatTag compatibility marker; no optional plugin classes are loaded. */
    public boolean isNpc(Player player) {
        return player != null && player.hasMetadata("NPC");
    }

    /** AuthMe's chat restriction has its own permission bypass. */
    public boolean mayChat(Player player) {
        return !isBlocked(player) || config().allowChat()
            || (player != null && player.hasPermission("authme.allowchatbeforelogin"));
    }

    public boolean isAllowedCommand(String command) {
        return isAllowedCommand(null, command);
    }

    public boolean isAllowedCommand(Player player, String command) {
        if (player != null && isBlocked(player)
            && config().quickCommandsDenyBeforeMilliseconds() > 0L) {
            Session session = sessions.get(player.getUniqueId());
            if (quickCommandProtectionEnabled(player) && session != null
                && System.currentTimeMillis() - session.joinTime < config().quickCommandsDenyBeforeMilliseconds()) {
                player.kickPlayer("Please wait before issuing commands.");
                return false;
            }
        }
        String normalized = normalizeCommand(command);
        for (String allowed : config().allowedCommands()) {
            if (normalizeCommand(allowed).equals(normalized)) return true;
        }
        return false;
    }

    /**
     * AuthMe's quick-command node enables the protection; it is not an opt-out node.
     * If the optional permission provider is unavailable, the configured default remains
     * fail-closed so a missing bridge cannot silently disable the guard.
     */
    private boolean quickCommandProtectionEnabled(Player player) {
        if (player == null) return false;
        return QuickCommandPolicy.enabled(config().permissionCheckEnabled(),
            player.hasPermission("authme.player.protection.quickcommandsprotection")
                || player.hasPermission("authme.player.*"), PermissionBridge.providerPresent());
    }

    public boolean hideChatFrom(Player viewer) {
        return viewer != null && config().hideChat() && isBlocked(viewer);
    }

    private boolean countryAllowed(Player player, String address) {
        if (player != null && player.hasPermission("authme.bypasscountrycheck")) return true;
        GeoIpPolicy policy = geoIp;
        return policy == null || policy.isAllowed(address);
    }

    public boolean mayMove(Player player, Location from, Location to) {
        if (!isBlocked(player)) return true;
        if (!config().allowMovement()) return false;
        double radius = config().allowedMovementRadius();
        Session session = sessions.get(player.getUniqueId());
        if (radius <= 0 || session == null || session.joinLocation == null || to == null
            || !java.util.Objects.equals(session.joinLocation.getWorld(), to.getWorld())) return true;
        return session.joinLocation.distanceSquared(to) <= radius * radius;
    }

    /** Executes the bounded AuthMe commands.yml hook set on the platform scheduler. */
    private void runEventCommands(String event, Player player, Session session) {
        if (player == null || session == null) return;
        java.util.List<EventCommands.ConfiguredCommand> configured = eventCommands.get(event);
        if (configured.isEmpty()) return;
        boolean needsCount = configured.stream().anyMatch(command ->
            command.accountsAtLeast() >= 0 || command.accountsLessThan() >= 0);
        if (needsCount) {
            String playerIp = session.ip;
            scheduler.runAsync(() -> {
                DataSource.QueryResult<java.util.List<String>> accounts =
                    service.accountsByIp(playerIp);
                if (!accounts.successful()) return;
                int count = Math.min(10_000, accounts.value() == null ? 0 : accounts.value().size());
                scheduler.runForPlayer(player, () -> {
                    if (!currentEventSession(session)) return;
                    for (EventCommands.ConfiguredCommand command : configured) {
                        if (command.accountsAtLeast() >= 0 && count < command.accountsAtLeast()) continue;
                        if (command.accountsLessThan() >= 0 && count >= command.accountsLessThan()) continue;
                        scheduleEventCommand(player, session, command);
                    }
                });
            });
            return;
        }
        for (EventCommands.ConfiguredCommand command : configured) {
            scheduleEventCommand(player, session, command);
        }
    }

    private void scheduleEventCommand(Player player, Session session,
                                      EventCommands.ConfiguredCommand command) {
        String playerName = player.getName();
        String playerIp = session.ip;
        String playerCountry = country(player);
        Runnable execute = () -> {
            if (!currentEventSession(session)) return;
            String text = command.command()
                .replace("%p", playerName.toLowerCase(java.util.Locale.ROOT))
                .replace("%nick", playerName)
                .replace("%ip", playerIp)
                .replace("%country", playerCountry);
            if (text.startsWith("/")) text = text.substring(1);
            if (text.isBlank()) return;
            if (command.executor() == EventCommands.Executor.PLAYER) {
                plugin.getServer().dispatchCommand(player, text);
            } else {
                plugin.getServer().dispatchCommand(plugin.getServer().getConsoleSender(), text);
            }
        };
        if (command.delayTicks() <= 0) {
            if (command.executor() == EventCommands.Executor.PLAYER) scheduler.runForPlayer(player, execute);
            else scheduler.runGlobal(execute);
        } else if (command.executor() == EventCommands.Executor.PLAYER) {
            scheduler.runDelayedForPlayer(player, execute, command.delayTicks());
        } else {
            scheduler.runDelayedGlobal(execute, command.delayTicks());
        }
    }

    private boolean currentEventSession(Session session) {
        return session != null && sessions.get(session.uuid) == session;
    }

    public void reloadAsync(CommandSender sender) {
        scheduler.runAsync(() -> {
            try {
                service.reload();
                eventCommands.load();
                antiBot = new AntiBotManager(service.config());
                geoIp = new GeoIpPolicy(service.config());
                messages = loadMessages(service.config());
                sendCommandResult(sender, "AuthMe configuration reloaded.");
            } catch (Exception exception) {
                plugin.getLogger().warning("AuthMe reload failed: " + exception.getMessage());
                sendCommandResult(sender, "AuthMe reload failed; the previous configuration remains active.");
            }
        });
    }

    private void sendCommandResult(CommandSender sender, String message) {
        Runnable task = () -> sender.sendMessage(message);
        if (sender instanceof Player player) scheduler.runForPlayer(player, task);
        else scheduler.runGlobal(task);
    }

    private Messages loadMessages(AuthMeConfig settings) {
        Messages next = new Messages(settings.configDir(), settings.messagesLanguage());
        return next.load() ? next : null;
    }

    private void showAuthenticationDialog(Player player, Session session) {
        if (player == null || session == null || session.authenticated || !session.accountResolved
            || isUnrestricted(player) || !config().dialogPostJoinEnabled() || session.dialogShown) return;
        boolean shown;
        if (session.totpPending) {
            shown = PaperDialogHelper.showTotp(player, config(), messages);
        } else if (session.registered) {
            shown = PaperDialogHelper.showLogin(player, config(), messages);
        } else if (config().registrationForce()) {
            shown = PaperDialogHelper.showRegister(player, config(), messages);
        } else {
            return;
        }
        session.dialogShown = shown;
    }

    private void closeAuthenticationDialog(Player player) {
        Session session = player == null ? null : sessions.get(player.getUniqueId());
        if (session == null || !session.dialogShown) return;
        PaperDialogHelper.close(player);
        session.dialogShown = false;
    }

    private void scheduleAutomaticMaintenance() {
        AuthMeConfig settings = config();
        if (settings.backupEnabled() && settings.backupOnStart()) scheduler.runAsync(this::backupNow);
        if (settings.purgeEnabled()) {
            collectPurgeBypassNames(bypassNames -> scheduler.runAsync(() -> purgeNow(bypassNames)));
        }

        long backupDelay = maintenanceDelayTicks(settings.backupIntervalHours());
        if (settings.backupEnabled() && backupDelay > 0) scheduleAutomaticBackup(backupDelay);
        if (settings.purgeEnabled()) scheduleAutomaticPurge(maintenanceDelayTicks(24));
    }

    private void scheduleAutomaticBackup(long delayTicks) {
        if (closed.get()) return;
        scheduler.runDelayedGlobal(() -> {
            if (closed.get()) return;
            scheduler.runAsync(() -> {
                backupNow();
                scheduleAutomaticBackup(delayTicks);
            });
        }, delayTicks);
    }

    private void scheduleAutomaticPurge(long delayTicks) {
        if (closed.get()) return;
        scheduler.runDelayedGlobal(() -> {
            if (closed.get()) return;
            collectPurgeBypassNames(bypassNames -> scheduler.runAsync(() -> {
                    purgeNow(bypassNames);
                    scheduleAutomaticPurge(delayTicks);
                }));
        }, delayTicks);
    }

    private boolean backupNow() {
        if (closed.get()) return false;
        synchronized (maintenanceLock) {
            if (closed.get()) return false;
            return writeBackupLocked();
        }
    }

    private boolean writeBackupLocked() {
        try {
            Path backupDirectory = plugin.getDataFolder().toPath().resolve("backups").normalize();
            if (Files.isSymbolicLink(backupDirectory)) return false;
            io.github.authme.fabric.util.SecureFileAccess.ensurePrivateDirectory(backupDirectory);
            String stamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
                .withZone(ZoneOffset.UTC).format(Instant.now());
            Path destination = backupDirectory.resolve("authme-" + stamp + ".sql").normalize();
            if (!destination.startsWith(backupDirectory)) return false;
            if (Files.exists(destination, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                destination = backupDirectory.resolve("authme-" + stamp + "-" + System.nanoTime() + ".sql")
                    .normalize();
                if (!destination.startsWith(backupDirectory)) return false;
            }
            return service.backup(destination);
        } catch (IOException | RuntimeException exception) {
            plugin.getLogger().warning("AuthMe backup failed: " + exception.getMessage());
            return false;
        }
    }

    private void purgeNow(Set<String> bypassNames) {
        if (closed.get()) return;
        synchronized (maintenanceLock) {
            if (closed.get()) return;
            long age = Math.min(Long.MAX_VALUE / 2,
                (long) Math.max(1, config().purgeDays()) * 86_400_000L);
            PurgeOutcome result = purgeAccounts(System.currentTimeMillis() - age, 10_000, bypassNames);
            if (!result.successful) plugin.getLogger().warning("AuthMe automatic purge failed.");
            else if (result.accounts > 0) plugin.getLogger().info(
                "AuthMe automatically purged " + result.accounts + " old account(s) and cleaned "
                    + result.files + " optional file(s).");
        }
    }

    private PurgeOutcome purgeAccounts(long cutoffMillis, int limit, Set<String> bypassNames) {
        DataSource.QueryResult<List<io.github.authme.fabric.datasource.PlayerAuth>> candidates =
            service.purgeCandidates(cutoffMillis, limit);
        if (!candidates.successful()) return new PurgeOutcome(0, 0, false);
        List<io.github.authme.fabric.datasource.PlayerAuth> all = candidates.value() == null
            ? List.of() : candidates.value();
        List<io.github.authme.fabric.datasource.PlayerAuth> removable = all.stream()
            .filter(account -> !bypassesPurge(account, bypassNames) && !hasLiveSession(account)).toList();
        if (removable.isEmpty()) return new PurgeOutcome(0, 0, true);
        List<io.github.authme.fabric.datasource.PlayerAuth> removed = new ArrayList<>();
        boolean successful = true;
        for (io.github.authme.fabric.datasource.PlayerAuth account : removable) {
            if (hasLiveSession(account)) continue;
            DataSource.OperationResult result = service.purgeIfUnchanged(account, cutoffMillis);
            if (!result.successful()) {
                successful = false;
                break;
            }
            if (result.affected() > 0) removed.add(account);
        }
        int files = io.github.authme.fabric.util.PurgeFileCleaner.clean(serverRoot(), config(),
            removed, onlineMode);
        return new PurgeOutcome(removed.size(), files, successful);
    }

    private boolean bypassesPurge(io.github.authme.fabric.datasource.PlayerAuth account,
                                  Set<String> bypassNames) {
        if (account == null) return false;
        String name = account.getRealName() == null || account.getRealName().isBlank()
            ? account.getName() : account.getRealName();
        return name != null && bypassNames != null
            && bypassNames.contains(name.toLowerCase(java.util.Locale.ROOT));
    }

    /** Async-safe check using immutable session names only; no Bukkit entity API is touched. */
    private boolean hasLiveSession(io.github.authme.fabric.datasource.PlayerAuth account) {
        if (account == null || account.getName() == null) return false;
        String candidate = account.getName();
        for (Session session : sessions.values()) {
            if (session != null && session.name.equalsIgnoreCase(candidate)) return true;
        }
        return false;
    }

    /** Captures each permission result on the owning entity thread before async deletion starts. */
    private void collectPurgeBypassNames(java.util.function.Consumer<Set<String>> callback) {
        scheduler.runGlobal(() -> {
            List<Player> players = List.copyOf(plugin.getServer().getOnlinePlayers());
            if (players.isEmpty()) {
                callback.accept(Set.of());
                return;
            }
            Set<String> result = ConcurrentHashMap.newKeySet();
            java.util.concurrent.atomic.AtomicInteger remaining =
                new java.util.concurrent.atomic.AtomicInteger(players.size());
            Runnable completeOne = () -> {
                if (remaining.decrementAndGet() == 0) callback.accept(Set.copyOf(result));
            };
            for (Player player : players) {
                boolean scheduled = scheduler.runForPlayer(player, () -> {
                    try {
                        if (player.isOnline() && player.hasPermission("authme.bypasspurge")
                            && player.getName() != null) {
                            result.add(player.getName().toLowerCase(java.util.Locale.ROOT));
                        }
                    } finally {
                        completeOne.run();
                    }
                });
                if (!scheduled) completeOne.run();
            }
        });
    }

    private Path serverRoot() {
        Path data = plugin.getDataFolder().toPath().toAbsolutePath().normalize();
        Path plugins = data.getParent();
        Path root = plugins == null ? null : plugins.getParent();
        return root == null ? data : root;
    }

    private static long maintenanceDelayTicks(int hours) {
        if (hours <= 0) return 0L;
        return Math.min(Long.MAX_VALUE / 2, (long) hours * 3_600L * 20L);
    }

    private record PurgeOutcome(int accounts, int files, boolean successful) { }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) return;
        synchronized (maintenanceLock) {
            if (config().backupEnabled() && config().backupOnStop()) writeBackupLocked();
            service.close();
        }
        sessions.clear();
        preJoinHandoffs.clear();
        busy.clear();
        joinedByAddress.clear();
    }

    private boolean begin(Player player) {
        if (!busy.add(player.getUniqueId())) {
            player.sendMessage("An authentication operation is already pending.");
            return false;
        }
        return true;
    }

    private void finish(Player player) { busy.remove(player.getUniqueId()); }

    private void scheduleTimeout(Player player, Session session) {
        int seconds = session.registered ? config().loginTimeout() : config().registrationTimeout();
        if (seconds <= 0) return;
        long ticks = Math.min(Integer.MAX_VALUE, Math.max(1L, seconds * 20L));
        scheduler.runDelayedForPlayer(player, () -> {
            Session current = sessions.get(player.getUniqueId());
            if (current == session && player.isOnline() && isBlocked(player)) {
                player.kickPlayer("Authentication timeout.");
            }
        }, ticks);
    }

    private void scheduleAuthenticationReminders(Player player, Session session) {
        int count = Math.min(100, Math.max(0, config().registrationMessageThreshold()));
        if (count == 0) return;
        long interval = Math.min(Integer.MAX_VALUE,
            Math.max(1L, config().registrationMessageIntervalSeconds()) * 20L);
        for (int index = 1; index <= count; index++) {
            long delay = Math.min(Integer.MAX_VALUE, interval * index);
            scheduler.runDelayedForPlayer(player, () -> {
                Session current = sessions.get(player.getUniqueId());
                if (current == session && player.isOnline() && isBlocked(player)) {
                    player.sendMessage(current.registered
                        ? "Please use /login before playing."
                        : "Please use /register before playing.");
                }
            }, delay);
        }
    }

    private static String address(Player player) {
        if (player.getAddress() == null || player.getAddress().getAddress() == null) return "unknown";
        return player.getAddress().getAddress().getHostAddress();
    }

    private String country(Player player) {
        GeoIpPolicy policy = geoIp;
        return policy == null ? "--" : policy.countryCode(address(player));
    }

    private static String normalizeCommand(String command) {
        if (command == null) return "";
        String value = command.trim().toLowerCase(java.util.Locale.ROOT);
        if (value.startsWith("/")) value = value.substring(1);
        int end = value.indexOf(' ');
        return end < 0 ? value : value.substring(0, end);
    }

    private static String loginMessage(PlatformAuthService.AccountResult result) {
        return switch (result) {
            case NOT_REGISTERED -> "This account is not registered.";
            case WRONG_PASSWORD -> "The password is incorrect.";
            case RATE_LIMITED -> "Too many authentication attempts; please wait and try again.";
            case LOGIN_LIMIT -> "The per-IP login limit has been reached.";
            case TOTP_REQUIRED -> "Two-factor authentication is required.";
            case INVALID_INPUT -> "The supplied authentication input is invalid.";
            case ALREADY_REGISTERED -> "This account is already registered.";
            default -> "The authentication database is unavailable.";
        };
    }

    private static String totpMessage(PlatformAuthService.AccountResult result) {
        return switch (result) {
            case WRONG_TOTP -> "The two-factor code is incorrect.";
            case TOTP_NOT_ENABLED -> "Two-factor authentication is not enabled.";
            case TOTP_ALREADY_ENABLED -> "Two-factor authentication is already enabled.";
            case INVALID_INPUT -> "The two-factor code is invalid.";
            default -> "The two-factor operation could not be completed.";
        };
    }

    private static String registrationMessage(PlatformAuthService.AccountResult result) {
        return switch (result) {
            case ALREADY_REGISTERED -> "This account is already registered.";
            case PASSWORD_MISMATCH -> "The passwords do not match.";
            case EMAIL_INVALID -> "The email address is invalid or not allowed.";
            case EMAIL_MISMATCH -> "The email addresses do not match.";
            case EMAIL_LIMIT, REGISTRATION_LIMIT -> "The registration limit has been reached.";
            case REGISTRATION_DISABLED -> "Registration is disabled.";
            case UNSAFE_PASSWORD -> "This password is not allowed.";
            case EMAIL_NOT_CONFIGURED -> "Email registration is not configured.";
            case EMAIL_SEND_FAILED -> "The registration email could not be sent.";
            case CAPTCHA_REQUIRED -> "A CAPTCHA is required before registration.";
            case INVALID_INPUT -> "The supplied registration input is invalid.";
            default -> "The authentication database is unavailable.";
        };
    }

    private static String emailMessage(PlatformAuthService.AccountResult result) {
        return switch (result) {
            case EMAIL_ADDED -> "Email address added.";
            case EMAIL_CHANGED -> "Email address changed.";
            case EMAIL_VERIFICATION_SENT -> "A verification code was sent to your email.";
            case EMAIL_RECOVERY_SENT -> "If the account and email match, a recovery code was sent.";
            case EMAIL_CONFIRMED -> "Email code accepted.";
            case EMAIL_CODE_INVALID -> "The email code is invalid or expired.";
            case EMAIL_INVALID -> "The email address is invalid or not allowed.";
            case EMAIL_MISMATCH -> "The email addresses do not match.";
            case EMAIL_LIMIT -> "The email registration limit has been reached.";
            case EMAIL_NOT_CONFIGURED -> "Email is not configured.";
            case EMAIL_SEND_FAILED -> "The email could not be sent.";
            case SUCCESS -> "Email operation completed.";
            default -> "The email operation could not be completed.";
        };
    }

    private static String premiumMessage(PlatformAuthService.AccountResult result) {
        return switch (result) {
            case PREMIUM_UNAVAILABLE -> "Premium mode is unavailable on this server.";
            case PREMIUM_MISMATCH -> "This online identity is not the registered Premium identity.";
            default -> "The Premium operation could not be completed.";
        };
    }

    private static String maskEmail(String email) {
        if (email == null || email.isBlank()) return "not set";
        int at = email.lastIndexOf('@');
        if (at <= 1) return "***";
        String local = email.substring(0, at);
        String domain = email.substring(at);
        return local.substring(0, 1) + "***" + domain;
    }

    private static final class Session {
        private final Player player;
        private final UUID uuid;
        private final String name;
        private final Location joinLocation;
        private final String ip;
        private final long connectionToken;
        private final long joinTime = System.currentTimeMillis();
        private volatile boolean registered;
        private volatile boolean accountResolved;
        private volatile boolean firstLogin;
        private volatile boolean portalAfterRegister;
        private volatile boolean delayedJoinAnnounced;
        private volatile boolean authenticated;
        private volatile boolean totpPending;
        private volatile boolean dialogShown;
        private volatile PreJoinSubmission preJoinSubmission;
        private volatile String pendingTotpSetupKey = "";
        private volatile boolean limboApplied;
        private volatile boolean blindApplied;
        private volatile boolean teleportedToSpawn;
        private volatile LimboStateStore.State limboState;
        private volatile PermissionBridge.GroupSnapshot groupSnapshot;

        private Session(Player player, Location joinLocation, String ip, long connectionToken) {
            this.player = player;
            this.uuid = player.getUniqueId();
            this.name = player.getName();
            this.joinLocation = joinLocation == null ? null : joinLocation.clone();
            this.ip = ip == null ? "unknown" : ip;
            this.connectionToken = connectionToken;
        }
    }

    private enum PreJoinKind { LOGIN, REGISTER, RECOVERY }

    private record PreJoinSubmission(PreJoinKind kind, String first, String second) { }

    private record PreJoinHandoff(PreJoinSubmission submission, String kickMessage, long expiresAt) { }
}
