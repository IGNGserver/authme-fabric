package io.github.authme.fabric.command;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;

import io.github.authme.fabric.AuthMe;
import io.github.authme.fabric.auth.AuthManager;
import io.github.authme.fabric.util.MinecraftText;
import io.github.authme.fabric.util.PermissionBridge;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.server.level.ServerPlayer;

/**
 * Registers all user and admin commands via the Fabric command API. The {@link AuthManager} is
 * resolved lazily at execution time (it is only created once the server has started, which happens
 * after command registration).
 *
 * <p>The command set mirrors AuthMe: {@code /login}, {@code /l}, {@code /register}, {@code /reg},
 * {@code /changepassword}, {@code /changepass}, {@code /logout}, {@code /unregister}, {@code /captcha},
 * {@code /2fa}, {@code /totp}, {@code /email}, {@code /premium}, {@code /freemium}, and the admin
 * tree {@code /authme ...} (level-3 only).
 */
public final class AuthMeCommands {

    private AuthMeCommands() {
    }

    public static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
        login(dispatcher, "login");
        login(dispatcher, "l");
        login(dispatcher, "log");
        registerCmd(dispatcher, "register");
        registerCmd(dispatcher, "reg");
        changepassword(dispatcher);
        logout(dispatcher);
        unregister(dispatcher);
        verification(dispatcher);
        captcha(dispatcher);
        totp(dispatcher, "2fa");
        totp(dispatcher, "totp");
        email(dispatcher);
        premium(dispatcher, "premium", false);
        premium(dispatcher, "freemium", true);
        authme(dispatcher);
    }

    private static AuthManager mgrOrReply(ServerPlayer p, CommandContext<CommandSourceStack> ctx) {
        AuthMe am = AuthMe.get();
        if (am == null || am.authManager() == null) {
            reply(ctx, "&cAuthMe is not ready yet.");
            return null;
        }
        return am.authManager();
    }

    // ------------------------------------------------- /login <password>
    private static void login(CommandDispatcher<CommandSourceStack> d, String name) {
        d.register(Commands.literal(name)
            .requires(src -> hasPlayerPermission(src, "authme.player.login"))
            .then(playerHelpBranch("login"))
            .then(Commands.argument("password", StringArgumentType.greedyString())

                .executes(ctx -> {
                    ServerPlayer p = player(ctx.getSource());
                    if (p == null) { reply(ctx, "&cThis command can only be run by a player."); return 0; }
                    AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                    m.login(p, StringArgumentType.getString(ctx, "password"));
                    return 1;
                }))
            .executes(ctx -> { reply(ctx, AuthMe.get().message("login.usage")); return 0; }));
    }

    // ------------------------------------------------- /register <password|email> [second argument]
    private static void registerCmd(CommandDispatcher<CommandSourceStack> d, String name) {
        d.register(Commands.literal(name)
            .requires(src -> hasPlayerPermission(src, "authme.player.register"))
            .then(playerHelpBranch("register"))
            .then(Commands.argument("registrationFirst", StringArgumentType.string())
                .executes(AuthMeCommands::registerFromCommand)
                .then(Commands.argument("registrationSecond", StringArgumentType.greedyString())
                    .executes(AuthMeCommands::registerFromCommand)))
            .executes(ctx -> { reply(ctx, AuthMe.get().message("reg.usage")); return 0; }));
    }

    private static int registerFromCommand(CommandContext<CommandSourceStack> ctx) {
        ServerPlayer p = player(ctx.getSource());
        if (p == null) { reply(ctx, "&cThis command can only be run by a player."); return 0; }
        AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
        String first = StringArgumentType.getString(ctx, "registrationFirst");
        String second;
        try {
            second = StringArgumentType.getString(ctx, "registrationSecond");
        } catch (IllegalArgumentException ignored) {
            second = null;
        }
        if (second == null && "help".equalsIgnoreCase(first)) return playerHelp(ctx, "register");
        m.register(p, first, second);
        return 1;
    }

    // ------------------------------------------------- /changepassword <old> <new> (alias /changepass)
    private static void changepassword(CommandDispatcher<CommandSourceStack> d) {
        for (String alias : new String[]{"changepassword", "changepass", "cp"}) {
            d.register(Commands.literal(alias)
                .requires(src -> hasPlayerPermission(src, "authme.player.changepassword"))
                .then(playerHelpBranch("changepassword"))
                .then(Commands.argument("oldpassword", StringArgumentType.string())
                    .then(Commands.argument("newpassword", StringArgumentType.greedyString())
                        .executes(ctx -> {
                            ServerPlayer p = player(ctx.getSource());
                            if (p == null) { reply(ctx, "&cThis command can only be run by a player."); return 0; }
                            AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                            m.changePassword(p, StringArgumentType.getString(ctx, "oldpassword"), StringArgumentType.getString(ctx, "newpassword"));
                            return 1;
                        })))
                .executes(ctx -> { reply(ctx, AuthMe.get().message("changepassword.usage")); return 0; }));
        }
    }

    private static void logout(CommandDispatcher<CommandSourceStack> d) {
        d.register(Commands.literal("logout")
            .requires(src -> hasPlayerPermission(src, "authme.player.logout"))
            .then(playerHelpBranch("logout"))
            .executes(ctx -> {
                ServerPlayer p = player(ctx.getSource());
                if (p == null) { reply(ctx, "&cThis command can only be run by a player."); return 0; }
                AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                m.logout(p);
                return 1;
            }));
    }

    private static void unregister(CommandDispatcher<CommandSourceStack> d) {
        for (String alias : new String[]{"unregister", "unreg"}) d.register(Commands.literal(alias)
            .requires(src -> hasPlayerPermission(src, "authme.player.unregister"))
            .then(playerHelpBranch("unregister"))
            .then(Commands.argument("password", StringArgumentType.greedyString())
                .executes(ctx -> {
                    ServerPlayer p = player(ctx.getSource());
                    if (p == null) { reply(ctx, "&cThis command can only be run by a player."); return 0; }
                    AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;

                    String password = StringArgumentType.getString(ctx, "password");
                    if ("help".equalsIgnoreCase(password)) return playerHelp(ctx, "unregister");
                    m.unregister(p, password);
                    return 1;
                }))
            .executes(ctx -> { reply(ctx, AuthMe.get().message("unregister.usage")); return 0; }));
    }

    private static void verification(CommandDispatcher<CommandSourceStack> d) {
        d.register(Commands.literal("verification")
            .requires(src -> hasPlayerPermission(src, "authme.player.security.verificationcode"))
            .then(playerHelpBranch("verification"))
            .then(Commands.argument("code", StringArgumentType.string()).executes(ctx -> {
                ServerPlayer p = player(ctx.getSource()); if (p == null) return 0;
                AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                String code = StringArgumentType.getString(ctx, "code");
                if ("help".equalsIgnoreCase(code)) return playerHelp(ctx, "verification");
                m.emailConfirm(p, code); return 1;
            }))
            .executes(ctx -> { reply(ctx, AuthMe.get().message("email.usage")); return 0; }));
    }

    private static void captcha(CommandDispatcher<CommandSourceStack> d) {
        d.register(Commands.literal("captcha")
            .requires(src -> hasPlayerPermission(src, "authme.player.captcha"))
            .then(playerHelpBranch("captcha"))
            .then(Commands.argument("code", StringArgumentType.greedyString())
                .executes(ctx -> {
                    ServerPlayer p = player(ctx.getSource());
                    if (p == null) return 0;
                    AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                    String code = StringArgumentType.getString(ctx, "code");
                    if ("help".equalsIgnoreCase(code)) return playerHelp(ctx, "captcha");
                    m.captcha(p, code);
                    return 1;
                }))
            .executes(ctx -> { reply(ctx, AuthMe.get().message("captcha.usage")); return 0; }));
    }

    // ------------------------------------------------- /2fa [add|remove <code>|<code>]
    private static void totp(CommandDispatcher<CommandSourceStack> d, String name) {
        d.register(Commands.literal(name)
            .then(playerHelpBranch("totp"))
            .then(Commands.literal("add").requires(src -> hasPlayerPermission(src, "authme.player.totpadd")).executes(ctx -> {
                ServerPlayer p = player(ctx.getSource());
                if (p == null) return 0;
                AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                m.totpEnable(p);
                return 1;
            }))
            .then(Commands.literal("confirm").requires(src -> hasPlayerPermission(src, "authme.player.totpadd")).then(Commands.argument("code", StringArgumentType.string()).executes(ctx -> {
                ServerPlayer p = player(ctx.getSource());
                if (p == null) return 0;
                AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                m.totpConfirm(p, StringArgumentType.getString(ctx, "code")); return 1;
            })))
            .then(Commands.literal("code").then(Commands.argument("code", StringArgumentType.string()).executes(ctx -> {
                ServerPlayer p = player(ctx.getSource());
                if (p == null) return 0;
                AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                m.totpVerify(p, StringArgumentType.getString(ctx, "code")); return 1;
            })))
            .then(Commands.literal("remove").requires(src -> hasPlayerPermission(src, "authme.player.totpremove"))
                .then(Commands.argument("code", StringArgumentType.string())
                    .executes(ctx -> {
                        ServerPlayer p = player(ctx.getSource());
                        if (p == null) return 0;
                        AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                m.totpDisable(p, StringArgumentType.getString(ctx, "code"));
                return 1;
            })))
            .then(Commands.argument("totpCode", StringArgumentType.string())
                .executes(ctx -> {
                    ServerPlayer p = player(ctx.getSource());
                    if (p == null) return 0;
                    AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                    String code = StringArgumentType.getString(ctx, "totpCode");
                    if ("help".equalsIgnoreCase(code)) return playerHelp(ctx, "totp");
                    m.totpVerify(p, code);
                    return 1;
                }))
            .executes(ctx -> { reply(ctx, AuthMe.get().message("totp.usage")); return 0; }));
    }

    // ------------------------------------------------- /email add|change|show|recover|code|setpassword
    private static void email(CommandDispatcher<CommandSourceStack> d) {
        d.register(Commands.literal("email")
            .then(playerHelpBranch("email"))
            .then(Commands.literal("add").requires(src -> hasPlayerPermission(src, "authme.player.email.add"))
                .then(Commands.argument("email", StringArgumentType.string())
                    .then(Commands.argument("verifyemail", StringArgumentType.string())
                        .executes(ctx -> {
                            ServerPlayer p = player(ctx.getSource());
                            if (p == null) return 0;
                            AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                            m.emailAdd(p, StringArgumentType.getString(ctx, "email"), StringArgumentType.getString(ctx, "verifyemail"));

                            return 1;
                        }))))
            .then(Commands.literal("change").requires(src -> hasPlayerPermission(src, "authme.player.email.change"))
                .then(Commands.argument("oldemail", StringArgumentType.string())
                    .then(Commands.argument("newemail", StringArgumentType.string())
                        .executes(ctx -> {
                            ServerPlayer p = player(ctx.getSource());
                            if (p == null) return 0;
                            AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                            m.emailChange(p, StringArgumentType.getString(ctx, "oldemail"), StringArgumentType.getString(ctx, "newemail"));
                            return 1;
                        }))))
            .then(Commands.literal("recover").requires(src -> hasPlayerPermission(src, "authme.player.email.recover"))
                .then(Commands.argument("email", StringArgumentType.string())
                    .executes(ctx -> {
                        ServerPlayer p = player(ctx.getSource());
                        if (p == null) return 0;
                        AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                        m.emailRecover(p, StringArgumentType.getString(ctx, "email"));
                        return 1;
                    })))
            .then(Commands.literal("code").requires(src -> hasPlayerPermission(src, "authme.player.email.recover"))
                .then(Commands.argument("code", StringArgumentType.string())
                    .executes(ctx -> {
                        ServerPlayer p = player(ctx.getSource());
                        if (p == null) return 0;
                        AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                        m.emailConfirm(p, StringArgumentType.getString(ctx, "code"));
                        return 1;
                    })))
            .then(Commands.literal("confirm").requires(src -> hasPlayerPermission(src, "authme.player.email.confirm"))
                .then(Commands.argument("code", StringArgumentType.string())
                    .executes(ctx -> {
                        ServerPlayer p = player(ctx.getSource());
                        if (p == null) return 0;
                        AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                        m.emailConfirm(p, StringArgumentType.getString(ctx, "code"));
                        return 1;
                    })))
            .then(Commands.literal("setpassword").requires(src -> hasPlayerPermission(src, "authme.player.email.recover"))
                .then(Commands.argument("password", StringArgumentType.greedyString())
                    .executes(ctx -> {
                        ServerPlayer p = player(ctx.getSource());
                        if (p == null) return 0;
                        AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                        m.emailSetRecoveredPassword(p, StringArgumentType.getString(ctx, "password"));
                        return 1;
                    })))
            .then(Commands.literal("show").requires(src -> hasPlayerPermission(src, "authme.player.email.see")).executes(ctx -> {
                ServerPlayer p = player(ctx.getSource());
                if (p == null) return 0;
                AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                m.emailShow(p);
                return 1;
            }))
            .executes(ctx -> { reply(ctx, AuthMe.get().message("email.usage")); return 0; }));
    }

    // ------------------------------------------------- /premium, /freemium
    private static void premium(CommandDispatcher<CommandSourceStack> d, String name, boolean disable) {

        d.register(Commands.literal(name)
            .requires(src -> hasPlayerPermission(src, disable ? "authme.player.freemium" : "authme.player.premium"))
            .then(playerHelpBranch(disable ? "freemium" : "premium"))
            .executes(ctx -> {
            ServerPlayer p = player(ctx.getSource());
            if (p == null) { reply(ctx, "&cThis command can only be run by a player."); return 0; }
            AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
            if (disable) m.premiumDisable(p); else m.premiumEnable(p);
            return 1;
        }));
    }

    // ------------------------------------------------- /authme <admin>
    private static void authme(CommandDispatcher<CommandSourceStack> d) {
        // The upstream command tree exposes /authme help and /authme version without an
        // admin node; every mutating/diagnostic child below still has its own requirement.
        // Keeping a requirement on the root would make those documented public commands
        // unreachable for ordinary players.
        d.register(Commands.literal("authme")
            .then(Commands.literal("register").requires(src -> hasAdminPermission(src, "authme.admin.register"))
                .then(Commands.argument("player", StringArgumentType.word())
                    .then(Commands.argument("password", StringArgumentType.greedyString())
                        .executes(ctx -> adminRegister(ctx)))))
            .then(Commands.literal("unregister").requires(src -> hasAdminPermission(src, "authme.admin.unregister"))
                .then(Commands.argument("player", StringArgumentType.word())
                    .executes(ctx -> adminUnregister(ctx))))
            .then(Commands.literal("setpassword").requires(src -> hasAdminPermission(src, "authme.admin.changepassword"))
                .then(Commands.argument("player", StringArgumentType.word())
                    .then(Commands.argument("password", StringArgumentType.greedyString())
                        .executes(ctx -> adminSetPassword(ctx)))))
            .then(Commands.literal("password").requires(src -> hasAdminPermission(src, "authme.admin.changepassword"))
                .then(Commands.argument("player", StringArgumentType.word())
                    .then(Commands.argument("password", StringArgumentType.greedyString())
                        .executes(ctx -> adminSetPassword(ctx)))))
            .then(Commands.literal("auth").requires(src -> hasAdminPermission(src, "authme.admin.forcelogin"))
                .then(Commands.argument("player", StringArgumentType.word())
                    .executes(ctx -> adminAuth(ctx))))
            .then(Commands.literal("forcelogin").requires(src -> hasAdminPermission(src, "authme.admin.forcelogin"))
                .executes(AuthMeCommands::adminAuthSelf)
                .then(Commands.argument("player", StringArgumentType.word())
                    .executes(ctx -> adminAuth(ctx))))
            .then(Commands.literal("unauth").requires(src -> hasAdminPermission(src, "authme.admin.forcelogin"))
                .then(Commands.argument("player", StringArgumentType.word())
                    .executes(ctx -> adminUnauth(ctx))))
            .then(Commands.literal("accountdata").requires(src -> hasAdminPermission(src, "authme.admin.lastlogin"))
                .then(Commands.argument("player", StringArgumentType.word())
                    .executes(ctx -> {
                        AuthManager m = checkMgr(ctx); if (m == null) return 0;
                        String target = StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT);
                        m.accountData(target, message -> reply(ctx, message));
                        return 1;
                    })))
            .then(Commands.literal("lastlogin").requires(src -> hasAdminPermission(src, "authme.admin.lastlogin"))
                .executes(AuthMeCommands::adminAccountDataSelf)
                .then(Commands.argument("player", StringArgumentType.word()).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    m.accountData(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message)); return 1;
                })))
            .then(Commands.literal("accounts").requires(src -> hasAdminPermission(src, "authme.admin.accounts"))
                .executes(AuthMeCommands::adminAccountsSelf)
                .then(Commands.argument("player", StringArgumentType.word()).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    m.accounts(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message)); return 1;
                })))
            .then(Commands.literal("getip").requires(src -> hasAdminPermission(src, "authme.admin.getip"))
                .then(Commands.argument("player", StringArgumentType.word()).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    m.adminGetIp(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message)); return 1;
                })))
            .then(Commands.literal("email")
                .requires(src -> hasAdminPermission(src, "authme.admin.getemail")
                    || hasAdminPermission(src, "authme.admin.changemail"))
                .executes(AuthMeCommands::adminEmailSelf)
                .then(Commands.literal("get").requires(src -> hasAdminPermission(src, "authme.admin.getemail")).then(Commands.argument("player", StringArgumentType.word()).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    m.adminGetEmail(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message)); return 1;
                })))
                .then(Commands.literal("set").requires(src -> hasAdminPermission(src, "authme.admin.changemail")).then(Commands.argument("player", StringArgumentType.word())
                    .then(Commands.argument("email", StringArgumentType.greedyString()).executes(ctx -> {
                        AuthManager m = checkMgr(ctx); if (m == null) return 0;
                        m.adminSetEmail(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), StringArgumentType.getString(ctx, "email"), message -> reply(ctx, message)); return 1;
                    }))))
                .then(Commands.argument("player", StringArgumentType.word())
                    .requires(src -> hasAdminPermission(src, "authme.admin.getemail"))
                    .executes(ctx -> {
                        AuthManager m = checkMgr(ctx); if (m == null) return 0;
                        m.adminGetEmail(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message)); return 1;
                    })))
            .then(Commands.literal("getemail").requires(src -> hasAdminPermission(src, "authme.admin.getemail"))
                .then(Commands.argument("player", StringArgumentType.word()).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    m.adminGetEmail(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message)); return 1;
                })))
            .then(Commands.literal("setemail").requires(src -> hasAdminPermission(src, "authme.admin.changemail"))
                .then(Commands.argument("player", StringArgumentType.word())
                    .then(Commands.argument("email", StringArgumentType.greedyString()).executes(ctx -> {
                        AuthManager m = checkMgr(ctx); if (m == null) return 0;
                        m.adminSetEmail(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), StringArgumentType.getString(ctx, "email"), message -> reply(ctx, message)); return 1;
                    }))))
            .then(Commands.literal("totp")
                .then(Commands.literal("status").requires(src -> hasAdminPermission(src, "authme.admin.totpviewstatus")).then(Commands.argument("player", StringArgumentType.word()).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    m.adminTotpStatus(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message)); return 1;
                })))
                .then(Commands.literal("disable").requires(src -> hasAdminPermission(src, "authme.admin.totpdisable")).then(Commands.argument("player", StringArgumentType.word()).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    m.adminDisableTotp(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message)); return 1;
                })))
                .then(Commands.argument("player", StringArgumentType.word()).requires(src -> hasAdminPermission(src, "authme.admin.totpviewstatus")).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    m.adminTotpStatus(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message)); return 1;
                })))
            .then(Commands.literal("disabletotp").requires(src -> hasAdminPermission(src, "authme.admin.totpdisable"))
                .then(Commands.argument("player", StringArgumentType.word()).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    m.adminDisableTotp(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message)); return 1;
                })))
            .then(Commands.literal("premium").requires(src -> hasAdminPermission(src, "authme.admin.setpremium"))
                .then(Commands.argument("player", StringArgumentType.word()).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    m.adminPremium(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), true, message -> reply(ctx, message)); return 1;
                })))
            .then(Commands.literal("setpremium").requires(src -> hasAdminPermission(src, "authme.admin.setpremium"))
                .then(Commands.argument("player", StringArgumentType.word()).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    m.adminPremium(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), true, message -> reply(ctx, message)); return 1;
                })))
            .then(Commands.literal("freemium").requires(src -> hasAdminPermission(src, "authme.admin.setfreemium"))
                .then(Commands.argument("player", StringArgumentType.word()).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    m.adminPremium(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), false, message -> reply(ctx, message)); return 1;
                })))
            .then(Commands.literal("setfreemium").requires(src -> hasAdminPermission(src, "authme.admin.setfreemium"))
                .then(Commands.argument("player", StringArgumentType.word()).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    m.adminPremium(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), false, message -> reply(ctx, message)); return 1;
                })))
            .then(Commands.literal("spawn").requires(src -> hasAdminPermission(src, "authme.admin.spawn")).executes(ctx -> adminSpawn(ctx, false)))
            .then(Commands.literal("setspawn").requires(src -> hasAdminPermission(src, "authme.admin.setspawn")).executes(ctx -> adminSetSpawn(ctx, false)))
            .then(Commands.literal("firstspawn").requires(src -> hasAdminPermission(src, "authme.admin.firstspawn")).executes(ctx -> adminSpawn(ctx, true)))
            .then(Commands.literal("setfirstspawn").requires(src -> hasAdminPermission(src, "authme.admin.setfirstspawn")).executes(ctx -> adminSetSpawn(ctx, true)))
            .then(Commands.literal("resetpos").requires(src -> hasAdminPermission(src, "authme.admin.purgelastpos")).then(Commands.argument("player", StringArgumentType.greedyString()).executes(ctx -> {
                AuthManager m = checkMgr(ctx); if (m == null) return 0;
                String target = StringArgumentType.getString(ctx, "player").trim();
                if ("*".equals(target)) m.resetAllPositions(message -> reply(ctx, message));
                else m.resetPosition(target.toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message)); return 1;
            })))
            .then(Commands.literal("purge").requires(src -> hasAdminPermission(src, "authme.admin.purge"))
                .then(Commands.argument("days", StringArgumentType.word()).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    int days;
                    try { days = Integer.parseInt(StringArgumentType.getString(ctx, "days")); }
                    catch (NumberFormatException e) { reply(ctx, "&cDays must be a positive integer."); return 0; }
                    if (days < 1) { reply(ctx, "&cDays must be a positive integer."); return 0; }
                    m.purge(days, message -> reply(ctx, message)); return 1;
                }))
                .executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0; m.purge(message -> reply(ctx, message)); return 1;
                }))
            .then(Commands.literal("purgeplayer").requires(src -> hasAdminPermission(src, "authme.admin.purgeplayer")).then(Commands.argument("player", StringArgumentType.word())
                .executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    m.purgePlayer(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), false, message -> reply(ctx, message)); return 1;
                })
                .then(Commands.argument("option", StringArgumentType.word()).executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0;
                    if (!"force".equalsIgnoreCase(StringArgumentType.getString(ctx, "option"))) { reply(ctx, "&cOption must be 'force'."); return 0; }
                    m.purgePlayer(StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT), true, message -> reply(ctx, message)); return 1;
                }))))
            .then(Commands.literal("purgebannedplayers").requires(src -> hasAdminPermission(src, "authme.admin.purgebannedplayers")).executes(ctx -> {
                AuthManager m = checkMgr(ctx); if (m == null) return 0;
                m.purgeBannedPlayers(message -> reply(ctx, message)); return 1;
            }))
            .then(Commands.literal("switchantibot").requires(src -> hasAdminPermission(src, "authme.admin.switchantibot"))
                .then(Commands.argument("mode", StringArgumentType.word()).executes(ctx -> switchAntiBot(ctx,
                    StringArgumentType.getString(ctx, "mode"))))
                .executes(ctx -> switchAntiBot(ctx, null)))
            .then(Commands.literal("messages").requires(src -> hasAdminPermission(src, "authme.admin.updatemessages")).executes(ctx -> {
                int added = AuthMe.get().addMissingMessages();
                reply(ctx, AuthMe.get().message(added < 0 ? "database.error" : "admin.messagesUpdated", "count", Math.max(0, added))); return 1;
            }))
            .then(Commands.literal("recent").requires(src -> hasAdminPermission(src, "authme.admin.seerecent")).then(Commands.argument("limit", StringArgumentType.word()).executes(ctx -> {
                AuthManager m = checkMgr(ctx); if (m == null) return 0;
                int limit; try { limit = Integer.parseInt(StringArgumentType.getString(ctx, "limit")); } catch (NumberFormatException e) { limit = 10; }
                m.recent(limit, message -> reply(ctx, message)); return 1;
            })).executes(ctx -> { AuthManager m = checkMgr(ctx); if (m == null) return 0; m.recent(10, message -> reply(ctx, message)); return 1; }))
            .then(Commands.literal("debug").requires(src -> hasAdminPermission(src, "authme.debug.command"))
                .then(Commands.argument("child", StringArgumentType.word())
                    .executes(ctx -> adminDebug(ctx, StringArgumentType.getString(ctx, "child"), null, null))
                    .then(Commands.argument("arg1", StringArgumentType.word())
                        .executes(ctx -> adminDebug(ctx, StringArgumentType.getString(ctx, "child"), StringArgumentType.getString(ctx, "arg1"), null))
                        .then(Commands.argument("arg2", StringArgumentType.greedyString())
                            .executes(ctx -> adminDebug(ctx, StringArgumentType.getString(ctx, "child"), StringArgumentType.getString(ctx, "arg1"), StringArgumentType.getString(ctx, "arg2"))))))
                .executes(ctx -> {
                    AuthManager m = checkMgr(ctx); if (m == null) return 0; m.debug(message -> reply(ctx, message)); return 1;
                }))
            .then(Commands.literal("reload").requires(src -> hasAdminPermission(src, "authme.admin.reload")).executes(ctx -> {
                boolean reloaded = AuthMe.get().reload();
                reply(ctx, AuthMe.get().message(reloaded ? "admin.reloaded" : "database.error"));
                return 1;
            }))
            .then(Commands.literal("backup").requires(src -> hasAdminPermission(src, "authme.admin.backup")).executes(ctx -> {
                AuthManager m = checkMgr(ctx); if (m == null) return 0;
                m.backup(message -> reply(ctx, message));
                return 1;
            }))
            .then(Commands.literal("version").executes(ctx -> {
                reply(ctx, "&aAuthMe Fabric&7v" + AuthMe.version() + " &a- Fabric port of AuthMeReloaded (GPL-3.0).");
                return 1;
            }))
            .then(Commands.literal("help")
                .then(Commands.argument("query", StringArgumentType.greedyString()).executes(AuthMeCommands::adminHelp))
                .executes(AuthMeCommands::adminHelp))
            .then(Commands.literal("converter").requires(src -> hasAdminPermission(src, "authme.admin.converter"))
                .then(Commands.literal("list").executes(ctx -> {
                    reply(ctx, io.github.authme.fabric.converter.Converters.listing());
                    return 1;
                }))
                .then(Commands.argument("id", StringArgumentType.word())

                    .executes(ctx -> adminConverter(ctx, null))
                    .then(Commands.argument("arg", StringArgumentType.greedyString())
                        .executes(ctx -> adminConverter(ctx, StringArgumentType.getString(ctx, "arg"))))))
            .executes(ctx -> { reply(ctx, AuthMe.get().message("admin.usage")); return 0; }));
    }

    private static int adminRegister(CommandContext<CommandSourceStack> ctx) {
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        String target = StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT);
        m.adminRegister(target, StringArgumentType.getString(ctx, "password"),
            message -> reply(ctx, message));
        return 1;
    }

    private static int adminUnregister(CommandContext<CommandSourceStack> ctx) {
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        String target = StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT);
        m.adminUnregister(target, message -> reply(ctx, message));
        return 1;
    }

    private static int adminSetPassword(CommandContext<CommandSourceStack> ctx) {
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        String target = StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT);
        m.adminSetPassword(target, StringArgumentType.getString(ctx, "password"),
            message -> reply(ctx, message));
        return 1;
    }

    private static int adminAuth(CommandContext<CommandSourceStack> ctx) {
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        String target = StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT);
        m.adminAuth(target, message -> reply(ctx, message));
        return 1;
    }

    private static int adminAuthSelf(CommandContext<CommandSourceStack> ctx) {
        ServerPlayer player = player(ctx.getSource());
        if (player == null) { reply(ctx, AuthMe.get().message("admin.notPlayer")); return 0; }
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        m.adminAuth(player.getName().getString().toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message));
        return 1;
    }

    private static int adminAccountDataSelf(CommandContext<CommandSourceStack> ctx) {
        ServerPlayer player = player(ctx.getSource());
        if (player == null) { reply(ctx, AuthMe.get().message("admin.notPlayer")); return 0; }
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        m.accountData(player.getName().getString().toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message)); return 1;
    }

    private static int adminAccountsSelf(CommandContext<CommandSourceStack> ctx) {
        ServerPlayer player = player(ctx.getSource());
        if (player == null) { reply(ctx, AuthMe.get().message("admin.notPlayer")); return 0; }
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        m.accounts(player.getName().getString().toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message)); return 1;
    }

    private static int adminEmailSelf(CommandContext<CommandSourceStack> ctx) {
        ServerPlayer player = player(ctx.getSource());
        if (player == null) { reply(ctx, AuthMe.get().message("admin.notPlayer")); return 0; }
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        m.adminGetEmail(player.getName().getString().toLowerCase(java.util.Locale.ROOT), message -> reply(ctx, message)); return 1;
    }

    private static int adminUnauth(CommandContext<CommandSourceStack> ctx) {
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        String target = StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT);
        m.adminUnauth(target, message -> reply(ctx, message));
        return 1;
    }

    private static int switchAntiBot(CommandContext<CommandSourceStack> ctx, String mode) {
        if (AuthMe.get().antiBot() == null) { reply(ctx, "&cAntiBot is not ready."); return 0; }
        boolean enabled;
        if (mode == null || mode.isBlank() || "toggle".equalsIgnoreCase(mode)) {
            enabled = AuthMe.get().antiBot().toggle();
        } else if ("on".equalsIgnoreCase(mode) || "enable".equalsIgnoreCase(mode)
            || "enabled".equalsIgnoreCase(mode) || "true".equalsIgnoreCase(mode)) {
            AuthMe.get().antiBot().setEnabled(true); enabled = true;
        } else if ("off".equalsIgnoreCase(mode) || "disable".equalsIgnoreCase(mode)
            || "disabled".equalsIgnoreCase(mode) || "false".equalsIgnoreCase(mode)) {
            AuthMe.get().antiBot().setEnabled(false); enabled = false;
        } else {
            reply(ctx, "&cMode must be one of: on, off, toggle."); return 0;
        }
        reply(ctx, "&2AntiBot is now " + (enabled ? "enabled" : "disabled") + "."); return 1;
    }

    private static int adminDebug(CommandContext<CommandSourceStack> ctx, String child, String arg1, String arg2) {
        if (!hasDebugPermission(ctx.getSource(), child)) {
            reply(ctx, "&cYou do not have permission to use this debug section.");
            return 0;
        }
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        m.debug(child, arg1, arg2, message -> reply(ctx, message)); return 1;
    }

    private static com.mojang.brigadier.builder.LiteralArgumentBuilder<CommandSourceStack> playerHelpBranch(String topic) {
        return Commands.literal("help")
            .then(Commands.argument("query", StringArgumentType.greedyString())
                .executes(ctx -> playerHelp(ctx, topic)))
            .executes(ctx -> playerHelp(ctx, topic));
    }

    private static int playerHelp(CommandContext<CommandSourceStack> ctx, String topic) {
        String query = optionalArgument(ctx, "query").trim().toLowerCase(java.util.Locale.ROOT);
        java.util.List<String> lines = switch (topic) {
            case "login" -> java.util.List.of("/login <password>", "/l <password>", "/log <password>");
            case "register" -> java.util.List.of("/register <password> [verifyPassword]", "/register <password> <email>", "/reg <password> [verifyPassword]");
            case "logout" -> java.util.List.of("/logout");
            case "unregister" -> java.util.List.of("/unregister <password>", "/unreg <password>");
            case "changepassword" -> java.util.List.of("/changepassword <oldPassword> <newPassword>", "/changepass <oldPassword> <newPassword>", "/cp <oldPassword> <newPassword>");
            case "verification" -> java.util.List.of("/verification <code>", "Confirm the verification code sent to your email.");
            case "captcha" -> java.util.List.of("/captcha <captcha>", "Complete the captcha challenge before logging in.");
            case "totp" -> java.util.List.of("/2fa add", "/2fa confirm <code>", "/2fa code <code>", "/2fa remove <code>", "/totp add|confirm|code|remove");
            case "email" -> java.util.List.of("/email show", "/email add <email> <verifyEmail>", "/email change <oldEmail> <newEmail>", "/email recover <email>", "/email code <code>", "/email confirm <code>", "/email setpassword <password>");
            case "premium" -> java.util.List.of("/premium", "Mark this account as premium and use the online-mode identity.");
            case "freemium" -> java.util.List.of("/freemium", "Disable premium account mode for this account.");
            default -> java.util.List.of();
        };
        int sent = 0;
        for (String line : lines) {
            if (query.isEmpty() || line.toLowerCase(java.util.Locale.ROOT).contains(query)) {
                reply(ctx, "&7" + line);
                sent++;
            }
        }
        if (sent == 0) reply(ctx, "&cNo matching help entry.");
        return sent == 0 ? 0 : 1;
    }

    private static String optionalArgument(CommandContext<CommandSourceStack> ctx, String name) {
        try {
            return StringArgumentType.getString(ctx, name);
        } catch (IllegalArgumentException ignored) {
            return "";
        }
    }

    private static int adminHelp(CommandContext<CommandSourceStack> ctx) {
        String query = optionalArgument(ctx, "query").trim().toLowerCase(java.util.Locale.ROOT);
        java.util.List<String> lines = java.util.List.of(
            "/authme register <player> <password>",
            "/authme unregister <player>",
            "/authme setpassword <player> <password>",
            "/authme auth [player]", "/authme unauth <player>",
            "/authme forcelogin [player]", "/authme lastlogin <player>",
            "/authme accounts [player]", "/authme email [player]", "/authme setemail <player> <email>",
            "/authme getip <player>", "/authme totp <player> [status]", "/authme disabletotp <player>",
            "/authme spawn|setspawn|firstspawn|setfirstspawn", "/authme resetpos <player|*>",
            "/authme purge [days]", "/authme purgeplayer <player> [force]", "/authme purgebannedplayers",
            "/authme switchantibot [on|off|toggle]", "/authme messages", "/authme recent [limit]",
            "/authme debug [child] [arg]", "/authme reload", "/authme backup", "/authme version",
            "/authme converter list|<id> [path|table]"
        );
        reply(ctx, AuthMe.get().message("admin.usage"));
        int sent = 0;
        for (String line : lines) {
            if (query.isEmpty() || line.toLowerCase(java.util.Locale.ROOT).contains(query)) {
                reply(ctx, "&7" + line);
                sent++;
            }
        }
        if (sent == 0) reply(ctx, "&cNo matching admin help entry.");
        return sent == 0 ? 0 : 1;
    }

    private static int adminConverter(CommandContext<CommandSourceStack> ctx, String argument) {
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        String id = StringArgumentType.getString(ctx, "id").toLowerCase(java.util.Locale.ROOT);
        m.adminConverter(id, argument, (count, message) -> reply(ctx, message));
        return 1;
    }

    private static int adminSpawn(CommandContext<CommandSourceStack> ctx, boolean first) {
        ServerPlayer p = player(ctx.getSource());
        if (p == null) { reply(ctx, AuthMe.get().message("admin.notPlayer")); return 0; }
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        m.spawn(p, first, message -> reply(ctx, message)); return 1;
    }

    private static int adminSetSpawn(CommandContext<CommandSourceStack> ctx, boolean first) {
        ServerPlayer p = player(ctx.getSource());
        if (p == null) { reply(ctx, AuthMe.get().message("admin.notPlayer")); return 0; }
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        m.setSpawn(p, first, message -> reply(ctx, message)); return 1;
    }

    private static AuthManager checkMgr(CommandContext<CommandSourceStack> ctx) {
        AuthMe am = AuthMe.get();
        if (am == null || am.authManager() == null || !am.healthy()) {
            reply(ctx, "&cAuthMe is unavailable because the database is not healthy.");
            return null;
        }
        return am.authManager();
    }

    private static boolean hasAdminPermission(CommandSourceStack source, String node) {
        if (source.getEntity() == null) return true;
        if (source.hasPermission(3)) return true;
        return Boolean.TRUE.equals(PermissionBridge.check(source.getEntity().getUUID(), node))
            || Boolean.TRUE.equals(PermissionBridge.check(source.getEntity().getUUID(), "authme.admin.*"));
    }

    private static boolean hasPlayerPermission(CommandSourceStack source, String node) {
        if (source.getEntity() == null) return true;
        AuthMe am = AuthMe.get();
        if (am == null || am.config() == null || !am.config().permissionCheckEnabled()) return true;
        Boolean decision = PermissionBridge.check(source.getEntity().getUUID(), node);
        if (Boolean.TRUE.equals(decision)) return true;
        if (Boolean.TRUE.equals(PermissionBridge.check(source.getEntity().getUUID(), "authme.player.*"))) return true;
        if (node.startsWith("authme.player.email.")) {
            Boolean email = PermissionBridge.check(source.getEntity().getUUID(), "authme.player.email");
            if (Boolean.TRUE.equals(email)) return true;
        }
        return decision != null ? decision : !PermissionBridge.providerPresent();
    }

    private static boolean hasDebugPermission(CommandSourceStack source, String child) {
        if (!hasAdminPermission(source, "authme.debug.command")) return false;
        if (child == null || child.isBlank()) return true;
        String node = switch (child.toLowerCase(java.util.Locale.ROOT)) {
            case "country", "cty" -> "authme.debug.country";
            case "db" -> "authme.debug.db";
            case "group" -> "authme.debug.group";
            case "limbo" -> "authme.debug.limbo";
            case "mail" -> "authme.debug.mail";
            case "mysqldef" -> "authme.debug.mysqldef";
            case "perm" -> "authme.debug.perm";
            case "spawn" -> "authme.debug.spawn";
            case "stats" -> "authme.debug.stats";
            case "valid" -> "authme.debug.valid";
            default -> null;
        };
        // An unknown debug selector must not inherit the broad command permission.
        return node != null && hasAdminPermission(source, node);
    }

    private static boolean hasAnyAdminPermission(CommandSourceStack source) {
        if (source.getEntity() == null || source.hasPermission(3)) return true;
        if (Boolean.TRUE.equals(PermissionBridge.check(source.getEntity().getUUID(), "authme.debug.command"))) return true;
        if (Boolean.TRUE.equals(PermissionBridge.check(source.getEntity().getUUID(), "authme.admin.*"))) return true;
        String[] nodes = {"register", "unregister", "changepassword", "forcelogin", "lastlogin", "accounts",
            "getemail", "changemail", "getip", "totpviewstatus", "totpdisable", "spawn", "setspawn",
            "firstspawn", "setfirstspawn", "purgelastpos", "purge", "purgeplayer", "purgebannedplayers",
            "switchantibot", "reload", "converter", "updatemessages", "seerecent", "backup", "setpremium",
            "setfreemium"};
        for (String node : nodes) {
            if (Boolean.TRUE.equals(PermissionBridge.check(source.getEntity().getUUID(), "authme.admin." + node))) return true;
        }
        return false;
    }

    private static void reply(CommandContext<CommandSourceStack> ctx, String message) {
        ServerPlayer player = ctx.getSource().getEntity() instanceof ServerPlayer p ? p : null;
        ctx.getSource().sendSuccess(() -> MinecraftText.toComponent(player, message), false);
    }

    private static ServerPlayer player(CommandSourceStack source) {
        return source != null && source.getEntity() instanceof ServerPlayer p ? p : null;
    }
}
