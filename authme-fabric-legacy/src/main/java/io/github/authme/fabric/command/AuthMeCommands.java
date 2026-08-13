package io.github.authme.fabric.command;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;

import io.github.authme.fabric.AuthMe;
import io.github.authme.fabric.auth.AuthManager;
import io.github.authme.fabric.util.MinecraftText;
import net.minecraft.commands.CommandBuildContext;
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

    public static void register(CommandDispatcher<CommandSourceStack> dispatcher, CommandBuildContext ctx, Commands.CommandSelection sel) {
        login(dispatcher, "login");
        login(dispatcher, "l");
        registerCmd(dispatcher, "register");
        registerCmd(dispatcher, "reg");
        changepassword(dispatcher);
        logout(dispatcher);
        unregister(dispatcher);
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
            .then(Commands.argument("password", StringArgumentType.greedyString())
                .executes(ctx -> {
                    ServerPlayer p = ctx.getSource().getPlayer();
                    if (p == null) { reply(ctx, "&cThis command can only be run by a player."); return 0; }
                    AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                    m.login(p, StringArgumentType.getString(ctx, "password"));
                    return 1;
                }))
            .executes(ctx -> { reply(ctx, AuthMe.get().message("login.usage")); return 0; }));
    }

    // ------------------------------------------------- /register <password> <password>
    private static void registerCmd(CommandDispatcher<CommandSourceStack> d, String name) {
        d.register(Commands.literal(name)
            .then(Commands.argument("password", StringArgumentType.string())
                .then(Commands.argument("verifypassword", StringArgumentType.greedyString())
                    .executes(ctx -> {
                        ServerPlayer p = ctx.getSource().getPlayer();
                        if (p == null) { reply(ctx, "&cThis command can only be run by a player."); return 0; }
                        AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                        m.register(p, StringArgumentType.getString(ctx, "password"), StringArgumentType.getString(ctx, "verifypassword"));
                        return 1;
                    })))
            .executes(ctx -> { reply(ctx, AuthMe.get().message("reg.usage")); return 0; }));
    }

    // ------------------------------------------------- /changepassword <old> <new> (alias /changepass)
    private static void changepassword(CommandDispatcher<CommandSourceStack> d) {
        for (String alias : new String[]{"changepassword", "changepass"}) {
            d.register(Commands.literal(alias)
                .then(Commands.argument("oldpassword", StringArgumentType.string())
                    .then(Commands.argument("newpassword", StringArgumentType.greedyString())
                        .executes(ctx -> {
                            ServerPlayer p = ctx.getSource().getPlayer();
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
            .executes(ctx -> {
                ServerPlayer p = ctx.getSource().getPlayer();
                if (p == null) { reply(ctx, "&cThis command can only be run by a player."); return 0; }
                AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                m.logout(p);
                return 1;
            }));
    }

    private static void unregister(CommandDispatcher<CommandSourceStack> d) {
        d.register(Commands.literal("unregister")
            .then(Commands.argument("password", StringArgumentType.greedyString())
                .executes(ctx -> {
                    ServerPlayer p = ctx.getSource().getPlayer();
                    if (p == null) { reply(ctx, "&cThis command can only be run by a player."); return 0; }
                    AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                    m.unregister(p, StringArgumentType.getString(ctx, "password"));
                    return 1;
                }))
            .executes(ctx -> { reply(ctx, AuthMe.get().message("unregister.usage")); return 0; }));
    }

    private static void captcha(CommandDispatcher<CommandSourceStack> d) {
        d.register(Commands.literal("captcha")
            .then(Commands.argument("code", StringArgumentType.greedyString())
                .executes(ctx -> {
                    ServerPlayer p = ctx.getSource().getPlayer();
                    if (p == null) return 0;
                    AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                    m.captcha(p, StringArgumentType.getString(ctx, "code"));
                    return 1;
                }))
            .executes(ctx -> { reply(ctx, AuthMe.get().message("captcha.usage")); return 0; }));
    }

    // ------------------------------------------------- /2fa [add|remove <code>|<code>]
    private static void totp(CommandDispatcher<CommandSourceStack> d, String name) {
        d.register(Commands.literal(name)
            .then(Commands.literal("add").executes(ctx -> {
                ServerPlayer p = ctx.getSource().getPlayer();
                if (p == null) return 0;
                AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                m.totpEnable(p);
                return 1;
            }))
            .then(Commands.literal("remove")
                .then(Commands.argument("code", StringArgumentType.string())
                    .executes(ctx -> {
                        ServerPlayer p = ctx.getSource().getPlayer();
                        if (p == null) return 0;
                        AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                        m.totpDisable(p, StringArgumentType.getString(ctx, "code"));
                        return 1;
                    })))
            .then(Commands.argument("code", StringArgumentType.string())
                .executes(ctx -> {
                    ServerPlayer p = ctx.getSource().getPlayer();
                    if (p == null) return 0;
                    AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                    m.totpVerify(p, StringArgumentType.getString(ctx, "code"));
                    return 1;
                }))
            .executes(ctx -> { reply(ctx, AuthMe.get().message("totp.usage")); return 0; }));
    }

    // ------------------------------------------------- /email add|show
    private static void email(CommandDispatcher<CommandSourceStack> d) {
        d.register(Commands.literal("email")
            .then(Commands.literal("add")
                .then(Commands.argument("email", StringArgumentType.string())
                    .then(Commands.argument("verifyemail", StringArgumentType.string())
                        .executes(ctx -> {
                            ServerPlayer p = ctx.getSource().getPlayer();
                            if (p == null) return 0;
                            AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                            m.emailAdd(p, StringArgumentType.getString(ctx, "email"), StringArgumentType.getString(ctx, "verifyemail"));
                            return 1;
                        }))))
            .then(Commands.literal("show").executes(ctx -> {
                ServerPlayer p = ctx.getSource().getPlayer();
                if (p == null) return 0;
                AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
                m.emailShow(p);
                return 1;
            }))
            .executes(ctx -> { reply(ctx, AuthMe.get().message("email.usage")); return 0; }));
    }

    // ------------------------------------------------- /premium, /freemium
    private static void premium(CommandDispatcher<CommandSourceStack> d, String name, boolean disable) {
        d.register(Commands.literal(name).executes(ctx -> {
            ServerPlayer p = ctx.getSource().getPlayer();
            if (p == null) { reply(ctx, "&cThis command can only be run by a player."); return 0; }
            AuthManager m = mgrOrReply(p, ctx); if (m == null) return 0;
            if (disable) m.premiumDisable(p); else m.premiumEnable(p);
            return 1;
        }));
    }

    // ------------------------------------------------- /authme <admin>
    private static void authme(CommandDispatcher<CommandSourceStack> d) {
        d.register(Commands.literal("authme")
            .requires(src -> src.hasPermission(3))
            .then(Commands.literal("register")
                .then(Commands.argument("player", StringArgumentType.word())
                    .then(Commands.argument("password", StringArgumentType.greedyString())
                        .executes(ctx -> adminRegister(ctx)))))
            .then(Commands.literal("unregister")
                .then(Commands.argument("player", StringArgumentType.word())
                    .executes(ctx -> adminUnregister(ctx))))
            .then(Commands.literal("setpassword")
                .then(Commands.argument("player", StringArgumentType.word())
                    .then(Commands.argument("password", StringArgumentType.greedyString())
                        .executes(ctx -> adminSetPassword(ctx)))))
            .then(Commands.literal("auth")
                .then(Commands.argument("player", StringArgumentType.word())
                    .executes(ctx -> adminAuth(ctx))))
            .then(Commands.literal("unauth")
                .then(Commands.argument("player", StringArgumentType.word())
                    .executes(ctx -> adminUnauth(ctx))))
            .then(Commands.literal("accountdata")
                .then(Commands.argument("player", StringArgumentType.word())
                    .executes(ctx -> {
                        String target = StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT);
                        reply(ctx, AuthMe.get().message("admin.accountdata", "player", target, "date", "-", "ip", "-", "last", "-"));
                        return 1;
                    })))
            .then(Commands.literal("reload").executes(ctx -> {
                AuthMe.get().reload();
                reply(ctx, AuthMe.get().message("admin.reloaded"));
                return 1;
            }))
            .then(Commands.literal("backup").executes(ctx -> { reply(ctx, AuthMe.get().message("admin.backup")); return 1; }))
            .then(Commands.literal("version").executes(ctx -> {
                reply(ctx, "&aAuthMe Fabric&7v6.0.1 &a- Fabric port of AuthMeReloaded (GPL-3.0).");
                return 1;
            }))
            .then(Commands.literal("converter")
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
            () -> reply(ctx, AuthMe.get().message("admin.registered", "player", target)));
        return 1;
    }

    private static int adminUnregister(CommandContext<CommandSourceStack> ctx) {
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        String target = StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT);
        m.adminUnregister(target, () -> reply(ctx, AuthMe.get().message("admin.unregistered", "player", target)));
        return 1;
    }

    private static int adminSetPassword(CommandContext<CommandSourceStack> ctx) {
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        String target = StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT);
        m.adminSetPassword(target, StringArgumentType.getString(ctx, "password"),
            () -> reply(ctx, AuthMe.get().message("admin.setpassword", "player", target)));
        return 1;
    }

    private static int adminAuth(CommandContext<CommandSourceStack> ctx) {
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        String target = StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT);
        m.adminAuth(target, () -> reply(ctx, AuthMe.get().message("admin.authed", "player", target)));
        return 1;
    }

    private static int adminUnauth(CommandContext<CommandSourceStack> ctx) {
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        String target = StringArgumentType.getString(ctx, "player").toLowerCase(java.util.Locale.ROOT);
        m.adminUnauth(target, () -> reply(ctx, AuthMe.get().message("admin.unauthed", "player", target)));
        return 1;
    }

    private static int adminConverter(CommandContext<CommandSourceStack> ctx, String argument) {
        AuthManager m = checkMgr(ctx); if (m == null) return 0;
        String id = StringArgumentType.getString(ctx, "id").toLowerCase(java.util.Locale.ROOT);
        m.adminConverter(id, argument, (count, message) -> reply(ctx, message));
        return 1;
    }

    private static AuthManager checkMgr(CommandContext<CommandSourceStack> ctx) {
        AuthMe am = AuthMe.get();
        if (am == null || am.authManager() == null) { reply(ctx, "&cAuthMe is not ready yet."); return null; }
        return am.authManager();
    }

    private static void reply(CommandContext<CommandSourceStack> ctx, String message) {
        ctx.getSource().sendSuccess(() -> MinecraftText.toComponent(message), false);
    }
}