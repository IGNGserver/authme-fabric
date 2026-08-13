package io.github.authme.fabric.auth;

import io.github.authme.fabric.AuthMe;
import io.github.authme.fabric.antibot.AntiBotManager;
import io.github.authme.fabric.config.AuthMeConfig;
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
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.phys.Vec3;

import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

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
    private long tickCounter;

    public AuthManager(AuthMe auth) {
        this.auth = auth;
    }

    private AuthMeConfig cfg() { return auth.config(); }
    private DataSource ds() { return auth.dataSource(); }
    private PasswordSecurity sec() { return auth.passwordSecurity(); }

    // ===================================================================== join / quit

    public void onJoin(ServerPlayer player) {
        AntiBotManager ab = auth.antiBot();
        if (ab != null && ab.shouldBlockNewJoins()) {
            kick(player, auth.message("account_tempban"));
            return;
        }
        String name = realName(player);
        String lower = name.toLowerCase(Locale.ROOT);
        PlayerSession session = new PlayerSession(player.getUUID(), lower);
        session.lastIp = ip(player);
        session.joinTime = System.currentTimeMillis();
        session.frozenX = player.getX();
        session.frozenY = player.getY();
        session.frozenZ = player.getZ();
        session.frozenWorld = worldKey(player);
        sessions.put(lower, session);
        player.setInvulnerable(true);
        player.setDeltaMovement(Vec3.ZERO);

        if (ab != null) ab.notifyJoin(session.lastIp);

        CompletableFuture
            .supplyAsync(() -> ds().getAuth(lower))
            .thenAccept(a -> executeMain(() -> applyJoin(player, lower, session, a)));
    }

    private void applyJoin(ServerPlayer player, String lower, PlayerSession session, PlayerAuth authRow) {
        if (offline(player)) return;
        session.registered = (authRow != null);
        if (authRow == null) {
            if (!cfg().registrationEnabled()) {
                kick(player, auth.message("unknown_user"));
                return;
            }
            schedulePrompt(player, session, false);
            return;
        }
        session.lastLogin = authRow.getLastLogin() == null ? 0L : authRow.getLastLogin();

        boolean autoLogin = false;
        if (cfg().enablePremium() && authRow.getPremiumUuid() != null
            && authRow.getPremiumUuid().equals(player.getUUID())) {
            autoLogin = true;
        } else if (cfg().sessionEnabled() && authRow.hasSession()) {
            long now = System.currentTimeMillis();
            long timeout = cfg().sessionTimeoutMinutes() * 60_000L;
            boolean within = session.lastLogin > 0 && (now - session.lastLogin) <= timeout;
            boolean ipOk = !cfg().sessionOnlyIp()
                || (authRow.getLastIp() != null && authRow.getLastIp().equalsIgnoreCase(session.lastIp));
            if (within && ipOk) autoLogin = true;
        }

        if (autoLogin) {
            completeLogin(player, session, authRow);
            MinecraftText.send(player, auth.message("login.success_session"));
        } else {
            if (authRow.getTotpKey() != null && !authRow.getTotpKey().isEmpty()
                && TotpProvider.isPlausibleSecret(authRow.getTotpKey())) {
                session.pendingTotp = true;
                session.totpKey = authRow.getTotpKey();
                // password bypassed only after totp; not auto login
            }
            schedulePrompt(player, session, true);
        }
    }

    public void onDisconnect(ServerPlayer player) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.remove(lower);
        if (session == null) return;
        if (session.authenticated) {
            String ip = session.lastIp;
            double x = player.getX(), y = player.getY(), z = player.getZ();
            float yaw = player.getYRot(), pitch = player.getXRot();
            String world = worldKey(player);
            CompletableFuture.runAsync(() -> {
                long now = System.currentTimeMillis();
                ds().updateLastLogin(lower, now);
                if (cfg().saveQuitLocation()) {
                    ds().updateLocation(lower, x, y, z, yaw, pitch, world);
                }
                ds().setLogged(lower, false);
                if (!cfg().sessionEnabled()) {
                    ds().setSession(lower, false);
                }
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
        CompletableFuture
            .supplyAsync(() -> ds().getAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (offline(player)) return;
                if (a == null) {
                    MinecraftText.send(player, auth.message("login.notRegistered"));
                    return;
                }
                HashedPassword stored = a.toHashedPassword();
                PasswordSecurity.VerificationResult result = sec().verify(password, stored, lower);
                if (result == null) {
                    onWrongPassword(player, session, lower);
                    return;
                }
                if (result.isLegacy()) {
                    // re-hash with the primary algorithm
                    HashedPassword rehashed = sec().computeHash(password, lower);
                    CompletableFuture.runAsync(() -> ds().updatePassword(lower, rehashed));
                    Log.info("Rehashed legacy password for " + lower);
                }
                session.loginAttempts = 0;
                session.totpKey = a.getTotpKey();
                if (a.getTotpKey() != null && !a.getTotpKey().isEmpty()
                    && TotpProvider.isPlausibleSecret(a.getTotpKey())) {
                    session.pendingTotp = true;
                    session.captchaPending = false;
                    MinecraftText.send(player, auth.message("totp.required"));
                } else {
                    completeLogin(player, session, a);
                }
            }));
    }

    private void onWrongPassword(ServerPlayer player, PlayerSession session, String lower) {
        MinecraftText.send(player, auth.message("login.wrong"));
        session.loginAttempts++;
        if (cfg().captchaEnabled() && session.loginAttempts >= cfg().maxLoginTriesForCaptcha()) {
            session.captchaPending = true;
            session.captchaCode = RandomStringUtils.generateNum(Math.max(3, cfg().captchaLength()));
            MinecraftText.send(player, auth.message("captcha.required", "code", session.captchaCode));
        } else if (cfg().tempbanEnabled() && session.loginAttempts >= cfg().tempbanMaxLoginTries()) {
            kick(player, auth.message("account_tempban"));
            Log.info("Tempbanned " + lower + " for too many login attempts.");
        }
    }

    public void register(ServerPlayer player, String password, String verify) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null) return;
        if (session.authenticated) {
            MinecraftText.send(player, auth.message("already_logged_in"));
            return;
        }
        if (!cfg().registrationEnabled()) {
            MinecraftText.send(player, auth.message("reg.disabled"));
            return;
        }
        if (!password.equals(verify)) {
            MinecraftText.send(player, auth.message("reg.noMatch"));
            return;
        }
        if (password.length() < cfg().minPasswordLength()
            || password.length() > cfg().maxPasswordLength()) {
            MinecraftText.send(player, auth.message("reg.usage"));
            return;
        }
        if (cfg().unsafePasswords().contains(password.toLowerCase(Locale.ROOT))) {
            MinecraftText.send(player, auth.message("reg.unsafePassword"));
            return;
        }
        CompletableFuture
            .supplyAsync(() -> ds().isAuthAvailable(lower))
            .thenAccept(exists -> executeMain(() -> {
                if (offline(player)) return;
                if (exists) {
                    MinecraftText.send(player, auth.message("reg.already"));
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
                    .locX(session.frozenX)
                    .locY(session.frozenY)
                    .locZ(session.frozenZ)
                    .locWorld(session.frozenWorld)
                    .build();
                CompletableFuture.runAsync(() -> {
                    ds().saveAuth(pa);
                    finishRegister(player, lower, session, pa);
                });
            }));
    }

    private void finishRegister(ServerPlayer player, String lower, PlayerSession session, PlayerAuth pa) {
        executeMain(() -> {
            if (offline(player)) return;
            MinecraftText.send(player, auth.message("reg.success", "?", ""));
            completeLogin(player, session, pa);
        });
    }

    public void changePassword(ServerPlayer player, String oldPw, String newPw) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("not_logged_in"));
            return;
        }
        if (newPw.length() < cfg().minPasswordLength() || newPw.length() > cfg().maxPasswordLength()) {
            MinecraftText.send(player, auth.message("reg.usage"));
            return;
        }
        CompletableFuture
            .supplyAsync(() -> ds().getAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (a == null) { MinecraftText.send(player, auth.message("unknown_user", "player", realName(player))); return; }
                PasswordSecurity.VerificationResult r = sec().verify(oldPw, a.toHashedPassword(), lower);
                if (r == null) { MinecraftText.send(player, auth.message("changepassword.wrong")); return; }
                HashedPassword newHash = sec().computeHash(newPw, lower);
                CompletableFuture.runAsync(() -> ds().updatePassword(lower, newHash));
                MinecraftText.send(player, auth.message("changepassword.success"));
            }));
    }

    public void logout(ServerPlayer player) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("logout.notlogged"));
            return;
        }
        session.authenticated = false;
        session.pendingTotp = false;
        player.setInvulnerable(true);
        CompletableFuture.runAsync(() -> {
            ds().setLogged(lower, false);
            ds().setSession(lower, false);
        });
        MinecraftText.send(player, auth.message("logout.success"));
    }

    public void unregister(ServerPlayer player, String password) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null) return;
        CompletableFuture
            .supplyAsync(() -> ds().getAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (a == null) { MinecraftText.send(player, auth.message("unknown_user", "player", realName(player))); return; }
                PasswordSecurity.VerificationResult r = sec().verify(password, a.toHashedPassword(), lower);
                if (r == null) { MinecraftText.send(player, auth.message("unregister.wrong")); return; }
                CompletableFuture.runAsync(() -> ds().removeAuth(lower));
                sessions.remove(lower);
                MinecraftText.send(player, auth.message("unregister.success"));
                kick(player, auth.message("unregister.success"));
            }));
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
            .supplyAsync(() -> ds().getAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (a == null) return;
                session.pendingTotp = false;
                completeLogin(player, session, a);
                MinecraftText.send(player, auth.message("totp.success"));
            }));
    }

    public void totpEnable(ServerPlayer player) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("not_logged_in"));
            return;
        }
        CompletableFuture
            .supplyAsync(() -> ds().getAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (a != null && a.getTotpKey() != null && !a.getTotpKey().isEmpty()) {
                    MinecraftText.send(player, auth.message("totp.already"));
                    return;
                }
                String secret = TotpProvider.generateSecret();
                CompletableFuture.runAsync(() -> ds().updateTotpKey(lower, secret));
                MinecraftText.send(player, auth.message("totp.enabled", "key", secret));
                MinecraftText.send(player, "&7" + TotpProvider.otpAuthUri("AuthMe", realName(player), secret));
            }));
    }

    public void totpDisable(ServerPlayer player, String code) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("not_logged_in"));
            return;
        }
        CompletableFuture
            .supplyAsync(() -> ds().getAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (a == null || a.getTotpKey() == null || a.getTotpKey().isEmpty()) {
                    MinecraftText.send(player, auth.message("totp.notEnabled"));
                    return;
                }
                if (!TotpProvider.validateCode(a.getTotpKey(), code)) {
                    MinecraftText.send(player, auth.message("totp.wrong"));
                    return;
                }
                CompletableFuture.runAsync(() -> ds().updateTotpKey(lower, null));
                MinecraftText.send(player, auth.message("totp.disabled"));
            }));
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
        UUID uuid = player.getUUID();
        CompletableFuture.runAsync(() -> ds().updatePremiumUuid(lower, uuid))
            .thenRun(() -> executeMain(() -> MinecraftText.send(player, auth.message("premium.set"))));
    }

    public void premiumDisable(ServerPlayer player) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("not_logged_in"));
            return;
        }
        CompletableFuture.runAsync(() -> ds().updatePremiumUuid(lower, null))
            .thenRun(() -> executeMain(() -> MinecraftText.send(player, auth.message("premium.removed"))));
    }

    public void emailAdd(ServerPlayer player, String email, String verify) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        PlayerSession session = sessions.get(lower);
        if (session == null || !session.authenticated) {
            MinecraftText.send(player, auth.message("not_logged_in"));
            return;
        }
        if (email == null || !email.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$") || !email.equals(verify)) {
            if (!email.equals(verify)) {
                MinecraftText.send(player, auth.message("email.noMatch"));
            } else {
                MinecraftText.send(player, auth.message("email.invalid"));
            }
            return;
        }
        CompletableFuture.runAsync(() -> ds().updateEmail(lower, email));
        MinecraftText.send(player, auth.message("email.added"));
    }

    public void emailShow(ServerPlayer player) {
        String lower = realName(player).toLowerCase(Locale.ROOT);
        CompletableFuture
            .supplyAsync(() -> ds().getAuth(lower))
            .thenAccept(a -> executeMain(() -> {
                if (a == null) { MinecraftText.send(player, auth.message("unknown_user", "player", realName(player))); return; }
                MinecraftText.send(player, auth.message("email.show", "email", a.getEmail() == null ? "" : a.getEmail()));
            }));
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
            executeMain(onComplete);
        });
    }

    public void adminUnregister(String targetLower, Runnable onComplete) {
        CompletableFuture.runAsync(() -> {
            ds().removeAuth(targetLower);
            PlayerSession online = sessions.get(targetLower);
            if (online != null) {
                online.authenticated = false;
                executeMain(() -> {
                    net.minecraft.server.level.ServerPlayer p = onlinePlayer(online.uuid);
                    if (p != null) kick(p, auth.message("unregister.success"));
                });
            }
            executeMain(onComplete);
        });
    }

    public void adminSetPassword(String targetLower, String password, Runnable onComplete) {
        HashedPassword hp = sec().computeHash(password, targetLower);
        CompletableFuture.runAsync(() -> {
            ds().updatePassword(targetLower, hp);
            executeMain(onComplete);
        });
    }

    public void adminAuth(String targetLower, Runnable onComplete) {
        CompletableFuture.runAsync(() -> {
            ds().setLogged(targetLower, true);
            PlayerSession online = sessions.get(targetLower);
            if (online != null) {
                executeMain(() -> {
                    online.authenticated = true;
                    online.pendingTotp = false;
                    ServerPlayer p = onlinePlayer(online.uuid);
                    if (p != null) {
                        p.setInvulnerable(false);
                        MinecraftText.send(p, auth.message("login.success"));
                    }
                });
            }
            executeMain(onComplete);
        });
    }

    public void adminUnauth(String targetLower, Runnable onComplete) {
        CompletableFuture.runAsync(() -> {
            ds().setLogged(targetLower, false);
            PlayerSession online = sessions.get(targetLower);
            if (online != null) {
                executeMain(() -> {
                    online.authenticated = false;
                    online.pendingTotp = false;
                    ServerPlayer p = onlinePlayer(online.uuid);
                    if (p != null) {
                        p.setInvulnerable(true);
                        MinecraftText.send(p, auth.message("not_logged_in"));
                    }
                });
            }
            executeMain(onComplete);
        });
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
            } else if (r.getNote().equalsIgnoreCase("not implemented in this fabric port yet. tracked as a known limitation.")) {
                reply.accept(0, "&e" + id + "&7: " + r.getNote());
            } else {
                String note = r.getNote().isEmpty() ? "" : " (" + r.getNote() + ")";
                reply.accept(r.getImported(), "&2Imported &a" + r.getImported() + "&2, skipped &a" + r.getSkipped() + note);
            }
        }));
    }

    // ===================================================================== queries used by events / mixin

    public boolean isUnauthenticated(ServerPlayer player) {
        PlayerSession s = sessions.get(realName(player).toLowerCase(Locale.ROOT));
        return s == null || !s.authenticated;
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
        long now = System.currentTimeMillis();
        int chatRate = 5 * 20;
        int actionBarRate = 2 * 20;
        for (PlayerSession s : sessions.values()) {
            ServerPlayer p = onlinePlayer(s.uuid);
            if (p == null) continue;
            if (s.authenticated) continue;
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
            // prompt
            if (tickCounter % chatRate == 0) {
                schedulePrompt(p, s, s.registered);
            }
            if (tickCounter % (actionBarRate - 20) == 0) {
                MinecraftText.sendActionBar(p, "&eAuthMe &7» &a/login &7| &a/register");
            }
            // timeout
            int timeout = s.registered ? cfg().loginTimeout() : cfg().registerTimeout();
            int regTimeout = Math.max(timeout, cfg().registrationTimeout());
            int effective = Math.max(timeout, regTimeout);
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
        // keep session reference fresh
        session.lastIp = ip(player);
    }

    private void completeLogin(ServerPlayer player, PlayerSession session, PlayerAuth authRow) {
        session.authenticated = true;
        session.pendingTotp = false;
        String lower = session.name;
        CompletableFuture.runAsync(() -> {
            long now = System.currentTimeMillis();
            ds().setLogged(lower, true);
            ds().updateIp(lower, session.lastIp);
            ds().updateLastLogin(lower, now);
            ds().setSession(lower, cfg().sessionEnabled());
        });
        // restore quit location if it belongs to the current dimension
        String targetWorld = authRow.getLocWorld();
        if (targetWorld != null && !targetWorld.isEmpty() && !targetWorld.equalsIgnoreCase("world")
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
        MinecraftText.send(player, auth.message("login.success"));
    }

    private void kick(ServerPlayer player, String message) {
        try {
            player.connection.disconnect(MinecraftText.toComponent(message));
        } catch (Exception e) {
            Log.error("Failed to disconnect " + realName(player), e);
        }
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
        if (ip.startsWith("/")) ip = ip.substring(1);
        int colon = ip.indexOf(':');
        if (colon > 0) ip = ip.substring(0, colon);
        return ip;
    }

    private static String worldKey(ServerPlayer p) {
        try {
            return p.level().dimension().identifier().toString();
        } catch (Exception e) {
            return "minecraft:overworld";
        }
    }
}