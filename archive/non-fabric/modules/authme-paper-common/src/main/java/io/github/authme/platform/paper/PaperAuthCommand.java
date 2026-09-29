package io.github.authme.platform.paper;

import io.github.authme.fabric.converter.Converters;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Shared Bukkit command adapter; secrets are excluded from tab suggestions and plugin diagnostics. */
public final class PaperAuthCommand implements CommandExecutor, TabCompleter {

    private final PaperAuthRuntime runtime;

    public PaperAuthCommand(PaperAuthRuntime runtime) {
        this.runtime = runtime;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String root = command.getName().toLowerCase(Locale.ROOT);
        if ("authme".equals(root)) {
            return executeRoot(sender, args);
        }
        if (!(sender instanceof Player player)) {
            sender.sendMessage(ChatColor.RED + "This command is only available to players.");
            return true;
        }
        if (args.length > 0 && "help".equalsIgnoreCase(args[0])) {
            playerHelp(sender, root);
            return true;
        }
        switch (root) {
            case "login", "l" -> {
                if (!requirePlayer(sender, "authme.player.login")) return true;
                if (args.length != 1) return usage(sender, "/login <password>");
                runtime.login(player, args[0]);
            }
            case "register", "reg" -> {
                if (!requirePlayer(sender, "authme.player.register")) return true;
                if (args.length < 1 || args.length > 2) return usage(sender, "/register <password|email> [confirmation]");
                runtime.register(player, args[0], args.length == 2 ? args[1] : null);
            }
            case "captcha" -> {
                if (!requirePlayer(sender, "authme.player.captcha")) return true;
                if (args.length != 1) return usage(sender, "/captcha <code>");
                runtime.captcha(player, args[0]);
            }
            case "verification" -> {
                if (!requirePlayer(sender, "authme.player.security.verificationcode")) return true;
                if (args.length != 1) return usage(sender, "/verification <code>");
                runtime.confirmEmail(player, args[0]);
            }
            case "email" -> {
                String action = args.length == 0 ? "" : playerEmailAction(args[0]);
                String permission = switch (action) {
                    case "show" -> "authme.player.email.see";
                    case "add" -> "authme.player.email.add";
                    case "change" -> "authme.player.email.change";
                    case "recover", "recoverpassword" -> "authme.player.email.recover";
                    case "code" -> "authme.player.email.recover";
                    case "confirm" -> "authme.player.email.confirm";
                    case "setpassword" -> "authme.player.email.recover";
                    default -> null;
                };
                if (permission != null && !requirePlayer(sender, permission)) return true;
                if (args.length == 0 || "help".equalsIgnoreCase(args[0])) playerHelp(sender, root);
                else if (args.length == 1 && "show".equals(action)) runtime.showEmail(player);
                else if (args.length == 3 && "add".equals(action)) runtime.addEmail(player, args[1], args[2]);
                else if (args.length == 3 && "change".equals(action)) runtime.changeEmail(player, args[1], args[2]);
                else if (args.length == 2 && "recover".equals(action)) runtime.recoverEmail(player, args[1]);
                else if (args.length == 2 && ("code".equals(action) || "confirm".equals(action))) runtime.confirmEmail(player, args[1]);
                else if (args.length == 2 && "setpassword".equals(action)) runtime.setRecoveredPassword(player, args[1]);
                else return usage(sender, "/email add|change|show|recover|code|setpassword ...");
            }
            case "premium" -> {
                if (!requirePlayer(sender, "authme.player.premium")) return true;
                if (args.length != 0) return usage(sender, "/premium");
                runtime.enablePremium(player);
            }
            case "freemium" -> {
                if (!requirePlayer(sender, "authme.player.freemium")) return true;
                if (args.length != 0) return usage(sender, "/freemium");
                runtime.disablePremium(player);
            }
            case "logout" -> {
                if (!requirePlayer(sender, "authme.player.logout")) return true;
                if (args.length != 0) return usage(sender, "/logout");
                runtime.logout(player);
            }
            case "unregister" -> {
                if (!requirePlayer(sender, "authme.player.unregister")) return true;
                if (args.length != 1) return usage(sender, "/unregister <password>");
                runtime.unregister(player, args[0]);
            }
            case "changepassword", "changepass" -> {
                if (!requirePlayer(sender, "authme.player.changepassword")) return true;
                if (args.length != 2) return usage(sender, "/changepassword <old> <new>");
                runtime.changePassword(player, args[0], args[1]);
            }
            case "2fa", "totp" -> {
                String action = args.length == 0 ? "" : playerTotpAction(args[0]);
                String permission = args.length > 0 && ("add".equals(action) || "confirm".equals(action))
                    ? "authme.player.totpadd"
                    : args.length > 0 && "remove".equals(action)
                        ? "authme.player.totpremove" : "authme.player.totp";
                if (!requirePlayer(sender, permission)) return true;
                if (args.length == 0 || "help".equalsIgnoreCase(args[0])) playerHelp(sender, root);
                else if (args.length == 1 && "add".equals(action)) runtime.enableTotp(player);
                else if (args.length == 2 && "confirm".equals(action)) runtime.confirmTotp(player, args[1]);
                else if (args.length == 2 && "remove".equals(action)) runtime.disableTotp(player, args[1]);
                else if (args.length == 2 && "code".equals(action)) runtime.verifyTotp(player, args[1]);
                else if (args.length == 1) runtime.verifyTotp(player, args[0]);
                else return usage(sender, "/2fa <code>|enable|confirm <code>|disable <code>");
            }
            default -> { return false; }
        }
        return true;
    }

    private boolean executeRoot(CommandSender sender, String[] args) {
        if (args.length == 0) {
            sender.sendMessage(ChatColor.YELLOW + "AuthMe platform bridge is active.");
            return true;
        }
        String sub = rootSubcommand(args[0]);
        if ("reload".equals(sub)) {
            if (!hasAdmin(sender, "authme.admin.reload")) {
                sender.sendMessage(ChatColor.RED + "You do not have permission to reload AuthMe.");
                return true;
            }
            runtime.reloadAsync(sender);
            return true;
        }
        if ("version".equals(sub)) {
            sender.sendMessage(ChatColor.GOLD + "==========[ AuthMe ABOUT ]==========");
            sender.sendMessage(ChatColor.GOLD + "Version: " + ChatColor.WHITE
                + "AuthMe 6.0.1-fabric.2-SNAPSHOT");
            sender.sendMessage(ChatColor.GOLD + "Platform: " + ChatColor.WHITE + "Bukkit/Paper bridge");
            sender.sendMessage(ChatColor.GOLD + "Website: " + ChatColor.WHITE
                + "https://github.com/AuthMe/AuthMeReloaded");
            sender.sendMessage(ChatColor.GOLD + "License: " + ChatColor.WHITE + "GNU GPL v3.0");
            return true;
        }
        if ("help".equals(sub)) {
            rootHelp(sender, args.length > 1 ? args[1] : null);
            return true;
        }
        if ("forcelogin".equals(sub) && (args.length == 1 || args.length == 2)
            && hasAdmin(sender, "authme.admin.forcelogin")) {
            String target = targetOrSender(sender, args, 1);
            if (target == null) return usage(sender, "/authme forcelogin [player]");
            runtime.adminAuth(sender, target, true);
            return true;
        }
        if (("password".equals(sub) || "setpassword".equals(sub)) && args.length == 3
            && hasAdmin(sender, "authme.admin.changepassword")) {
            runtime.adminSetPassword(sender, args[1], args[2]);
            return true;
        }
        if (("lastlogin".equals(sub) || "accountdata".equals(sub)) && (args.length == 1 || args.length == 2)
            && hasAdmin(sender, "authme.admin.lastlogin")) {
            String target = targetOrSender(sender, args, 1);
            if (target == null) return usage(sender, "/authme lastlogin [player]");
            runtime.adminAccountData(sender, target);
            return true;
        }
        if ("accounts".equals(sub) && args.length == 1
            && sender instanceof Player player && hasPlayer(sender, "authme.player.seeownaccounts")) {
            runtime.playerAccounts(player);
            return true;
        }
        if ("accounts".equals(sub) && (args.length == 1 || args.length == 2)
            && hasAdmin(sender, "authme.admin.accounts")) {
            String target = targetOrSender(sender, args, 1);
            if (target == null) return usage(sender, "/authme accounts [player]");
            runtime.adminAccounts(sender, target);
            return true;
        }
        if ("email".equals(sub) && (args.length == 1 || args.length == 2)
            && hasAdmin(sender, "authme.admin.getemail")) {
            String target = targetOrSender(sender, args, 1);
            if (target == null) return usage(sender, "/authme email [player]");
            runtime.adminEmail(sender, target, null);
            return true;
        }
        if ("setemail".equals(sub) && args.length == 3
            && hasAdmin(sender, "authme.admin.changemail")) {
            runtime.adminEmail(sender, args[1], args[2]);
            return true;
        }
        if ("totp".equals(sub) && args.length == 2 && hasAdmin(sender, "authme.admin.totpviewstatus")) {
            runtime.adminTotp(sender, args[1], false);
            return true;
        }
        if ("disabletotp".equals(sub) && args.length == 2 && hasAdmin(sender, "authme.admin.totpdisable")) {
            runtime.adminTotp(sender, args[1], true);
            return true;
        }
        if ("debug".equals(sub) && args.length == 1 && hasDebugRoot(sender)) {
            runtime.adminDebug(sender, null, null, null);
            return true;
        }
        if ("debug".equals(sub) && args.length >= 2 && args.length <= 4
            && hasDebug(sender, args[1])) {
            runtime.adminDebug(sender, args[1], args.length >= 3 ? args[2] : null,
                args.length >= 4 ? args[3] : null);
            return true;
        }
        if ("converter".equals(sub) && hasAdmin(sender, "authme.admin.converter")) {
            if (args.length == 1 || (args.length == 2 && "list".equalsIgnoreCase(args[1]))) {
                runtime.adminConverterList(sender);
            } else if (args.length == 2 || args.length == 3) {
                runtime.adminConverter(sender, args[1], args.length == 3 ? args[2] : null);
            } else {
                usage(sender, "/authme converter list|<id> [path|table]");
            }
            return true;
        }
        if ("messages".equals(sub) && args.length == 1
            && hasAdmin(sender, "authme.admin.updatemessages")) {
            runtime.adminMessages(sender);
            return true;
        }
        if (("accounts".equals(sub) || "account".equals(sub)) && args.length == 1
            && sender instanceof Player player && hasPlayer(sender, "authme.player.seeownaccounts")) {
            runtime.playerAccounts(player);
            return true;
        }
        if (("switchantibot".equals(sub) || "toggleantibot".equals(sub) || "antibot".equals(sub))
            && (args.length == 1 || args.length == 2) && hasAdmin(sender, "authme.admin.switchantibot")) {
            Boolean enabled = null;
            if (args.length == 2) {
                if ("on".equalsIgnoreCase(args[1])) enabled = true;
                else if ("off".equalsIgnoreCase(args[1])) enabled = false;
                else return usage(sender, "/authme switchantibot [on|off]");
            }
            runtime.adminSwitchAntiBot(sender, enabled);
            return true;
        }
        if ("register".equals(sub) && args.length == 3 && hasAdmin(sender, "authme.admin.register")) {
            runtime.adminRegister(sender, args[1], args[2]);
            return true;
        }
        if (("unregister".equals(sub) && args.length == 2)
            && hasAdmin(sender, "authme.admin.unregister")) {
            runtime.adminUnregister(sender, args[1]);
            return true;
        }
        if (("setpassword".equals(sub) || "password".equals(sub)) && args.length == 3
            && hasAdmin(sender, "authme.admin.changepassword")) {
            runtime.adminSetPassword(sender, args[1], args[2]);
            return true;
        }
        if (("auth".equals(sub) || "forcelogin".equals(sub)) && args.length == 2
            && hasAdmin(sender, "authme.admin.forcelogin")) {
            runtime.adminAuth(sender, args[1], true);
            return true;
        }
        if ("unauth".equals(sub) && args.length == 2 && hasAdmin(sender, "authme.admin.forcelogin")) {
            runtime.adminAuth(sender, args[1], false);
            return true;
        }
        if (("accountdata".equals(sub) || "lastlogin".equals(sub)) && args.length == 2
            && hasAdmin(sender, "authme.admin.lastlogin")) {
            runtime.adminAccountData(sender, args[1]);
            return true;
        }
        if ("getip".equals(sub) && args.length == 2 && hasAdmin(sender, "authme.admin.getip")) {
            runtime.adminIp(sender, args[1]);
            return true;
        }
        if ("accounts".equals(sub) && args.length == 2 && hasAdmin(sender, "authme.admin.accounts")) {
            runtime.adminAccounts(sender, args[1]);
            return true;
        }
        if ("recent".equals(sub) && (args.length == 1 || args.length == 2)
            && hasAdmin(sender, "authme.admin.seerecent")) {
            int limit = 10;
            if (args.length == 2) {
                try { limit = Integer.parseInt(args[1]); } catch (NumberFormatException ignored) { }
            }
            runtime.adminRecent(sender, limit);
            return true;
        }
        if ("purge".equals(sub) && args.length == 2
            && hasAdmin(sender, "authme.admin.purge")) {
            Integer days = parseInteger(args[1]);
            if (days == null || days < 30) return usage(sender, "/authme purge <days> (minimum: 30)");
            runtime.adminPurge(sender, days);
            return true;
        }
        if ("resetpos".equals(sub) && args.length == 2 && hasAdmin(sender, "authme.admin.purgelastpos")) {
            runtime.adminResetPosition(sender, args[1]);
            return true;
        }
        if ("purgeplayer".equals(sub) && (args.length == 2 || args.length == 3)
            && hasAdmin(sender, "authme.admin.purgeplayer")) {
            runtime.adminPurgePlayer(sender, args[1], args.length == 3 && "force".equalsIgnoreCase(args[2]));
            return true;
        }
        if ("purgebannedplayers".equals(sub) && args.length == 1
            && hasAdmin(sender, "authme.admin.purgebannedplayers")) {
            runtime.adminPurgeBannedPlayers(sender);
            return true;
        }
        if ("spawn".equals(sub) && args.length == 1 && hasAdmin(sender, "authme.admin.spawn")) {
            runtime.adminSpawn(sender, false);
            return true;
        }
        if ("setspawn".equals(sub) && args.length == 1 && hasAdmin(sender, "authme.admin.setspawn")) {
            runtime.adminSetSpawn(sender, false);
            return true;
        }
        if ("firstspawn".equals(sub) && args.length == 1 && hasAdmin(sender, "authme.admin.firstspawn")) {
            runtime.adminSpawn(sender, true);
            return true;
        }
        if ("setfirstspawn".equals(sub) && args.length == 1 && hasAdmin(sender, "authme.admin.setfirstspawn")) {
            runtime.adminSetSpawn(sender, true);
            return true;
        }
        if ("backup".equals(sub) && args.length == 1 && hasAdmin(sender, "authme.admin.backup")) {
            runtime.adminBackup(sender);
            return true;
        }
        if ("email".equals(sub) && args.length == 4 && "set".equalsIgnoreCase(args[1])
            && hasAdmin(sender, "authme.admin.changemail")) {
            runtime.adminEmail(sender, args[2], args[3]);
            return true;
        }
        if ("email".equals(sub) && args.length == 3 && "get".equalsIgnoreCase(args[1])
            && hasAdmin(sender, "authme.admin.getemail")) {
            runtime.adminEmail(sender, args[2], null);
            return true;
        }
        if ("totp".equals(sub) && args.length == 3 && "status".equalsIgnoreCase(args[1])
            && hasAdmin(sender, "authme.admin.totpviewstatus")) {
            runtime.adminTotp(sender, args[2], false);
            return true;
        }
        if ("totp".equals(sub) && args.length == 3 && "disable".equalsIgnoreCase(args[1])
            && hasAdmin(sender, "authme.admin.totpdisable")) {
            runtime.adminTotp(sender, args[2], true);
            return true;
        }
        if (("premium".equals(sub) || "setpremium".equals(sub)) && args.length == 2
            && hasAdmin(sender, "authme.admin.setpremium")) {
            runtime.adminPremium(sender, args[1], true);
            return true;
        }
        if (("freemium".equals(sub) || "setfreemium".equals(sub)) && args.length == 2
            && hasAdmin(sender, "authme.admin.setfreemium")) {
            runtime.adminPremium(sender, args[1], false);
            return true;
        }
        sender.sendMessage(ChatColor.YELLOW + "Usage: /authme <admin-subcommand> ...");
        return true;
    }

    private static boolean usage(CommandSender sender, String message) {
        sender.sendMessage(ChatColor.YELLOW + "Usage: " + message);
        return true;
    }

    private static boolean hasAdmin(CommandSender sender, String node) {
        return sender.hasPermission(node) || sender.hasPermission("authme.admin")
            || sender.hasPermission("authme.admin.*");
    }

    private static boolean requirePlayer(CommandSender sender, String node) {
        if (sender.hasPermission(node) || sender.hasPermission("authme.player")
            || sender.hasPermission("authme.player.*")) return true;
        sender.sendMessage(ChatColor.RED + "You do not have permission to use this AuthMe command.");
        return false;
    }

    private static boolean hasPlayer(CommandSender sender, String node) {
        return sender.hasPermission(node) || sender.hasPermission("authme.player")
            || sender.hasPermission("authme.player.*");
    }

    private static boolean hasDebug(CommandSender sender, String child) {
        String node = switch (child == null ? "" : child.toLowerCase(Locale.ROOT)) {
            case "country", "cty" -> "country";
            case "db", "stats", "group", "limbo", "mail", "mysqldef", "perm", "spawn", "valid" -> child.toLowerCase(Locale.ROOT);
            default -> "";
        };
        return !node.isBlank() && (sender.hasPermission("authme.debug.command")
            || sender.hasPermission("authme.debug.*"))
            && (sender.hasPermission("authme.debug." + node) || sender.hasPermission("authme.debug.*"));
    }

    private static boolean hasDebugRoot(CommandSender sender) {
        return sender.hasPermission("authme.debug.command") || sender.hasPermission("authme.debug.*");
    }

    private static Integer parseInteger(String value) {
        try { return Integer.valueOf(value); } catch (NumberFormatException ignored) { return null; }
    }

    private static String rootSubcommand(String value) {
        String normalized = value == null ? "" : value.toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "r" -> "register";
            case "unr" -> "unregister";
            case "login" -> "forcelogin";
            case "changepassword", "changepass", "cp" -> "password";
            case "ll" -> "lastlogin";
            case "account" -> "accounts";
            case "mail", "getemail", "getmail" -> "email";
            case "setmail", "chgemail", "chgmail" -> "setemail";
            case "ip" -> "getip";
            case "2fa" -> "totp";
            case "disable2fa", "deletetotp", "delete2fa" -> "disabletotp";
            case "home" -> "spawn";
            case "chgspawn" -> "setspawn";
            case "firsthome" -> "firstspawn";
            case "chgfirstspawn" -> "setfirstspawn";
            case "delete" -> "purge";
            case "purgelastposition", "purgelastpos", "resetposition", "resetlastposition", "resetlastpos" -> "resetpos";
            case "purgebannedplayer", "deletebannedplayers", "deletebannedplayer" -> "purgebannedplayers";
            case "toggleantibot", "antibot" -> "switchantibot";
            case "rld" -> "reload";
            case "ver", "v", "about", "info" -> "version";
            case "convert", "conv" -> "converter";
            case "msg" -> "messages";
            case "setpremium" -> "premium";
            case "setfreemium" -> "freemium";
            case "dbg" -> "debug";
            default -> normalized;
        };
    }

    private static String playerEmailAction(String value) {
        return switch (value == null ? "" : value.toLowerCase(Locale.ROOT)) {
            case "myemail" -> "show";
            case "addemail", "addmail" -> "add";
            case "changeemail", "changemail" -> "change";
            case "recovery", "recoveremail", "recovermail", "recoverpassword" -> "recover";
            case "confirmemail" -> "confirm";
            default -> value == null ? "" : value.toLowerCase(Locale.ROOT);
        };
    }

    private static String playerTotpAction(String value) {
        if (value == null) return "";
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "c" -> "code";
            case "enable" -> "add";
            case "disable" -> "remove";
            default -> value.toLowerCase(Locale.ROOT);
        };
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        String commandName = command.getName().toLowerCase(Locale.ROOT);
        if ("email".equals(commandName)) {
            if (args.length != 1) return List.of();
            List<String> values = new ArrayList<>();
            if (hasPlayer(sender, "authme.player.email.add")) values.add("add");
            if (hasPlayer(sender, "authme.player.email.change")) values.add("change");
            if (hasPlayer(sender, "authme.player.email.see")) values.add("show");
            if (hasPlayer(sender, "authme.player.email.recover")) {
                values.add("recover");
                values.add("code");
                values.add("setpassword");
            }
            if (hasPlayer(sender, "authme.player.email.confirm")) values.add("confirm");
            values.add("help");
            return filter(values, args[0]);
        }
        if (("2fa".equals(commandName) || "totp".equals(commandName)) && args.length == 1) {
            List<String> values = new ArrayList<>();
            if (hasPlayer(sender, "authme.player.totp")) values.add("code");
            if (hasPlayer(sender, "authme.player.totpadd")) values.add("add");
            if (hasPlayer(sender, "authme.player.totpadd")) values.add("confirm");
            if (hasPlayer(sender, "authme.player.totpremove")) values.add("remove");
            values.add("help");
            return filter(values, args[0]);
        }
        if (!"authme".equals(commandName)) return List.of();
        if (args.length == 1) {
            List<String> values = new ArrayList<>();
            for (String value : List.of("register", "unregister", "forcelogin", "password", "setpassword", "auth", "unauth",
                "accountdata", "lastlogin", "accounts", "getip", "email", "totp", "premium", "freemium", "recent", "purge",
                "resetpos", "purgeplayer", "purgebannedplayers", "spawn", "setspawn", "firstspawn", "setfirstspawn",
                "backup", "converter", "messages", "switchantibot", "debug", "disabletotp", "setemail", "reload", "version", "help")) {
                if (rootCompletionAllowed(sender, value)) values.add(value);
            }
            return filter(values, args[0]);
        }
        if (args.length == 2) {
            String sub = rootSubcommand(args[0]);
            if ("debug".equals(sub) && hasDebugRoot(sender)) {
                List<String> children = new ArrayList<>();
                for (String child : List.of("country", "db", "group", "limbo", "mail", "mysqldef", "perm", "spawn", "stats", "valid")) {
                    if (hasDebug(sender, child)) children.add(child);
                }
                return filter(children, args[1]);
            }
            if ("converter".equals(sub) && hasAdmin(sender, "authme.admin.converter")) {
                List<String> values = new ArrayList<>(Converters.ids());
                values.add("list");
                return filter(values, args[1]);
            }
            if ("email".equals(sub) && hasAdmin(sender, "authme.admin.getemail")) {
                return filter(List.of("get", "set"), args[1]);
            }
            if ("totp".equals(sub) && (hasAdmin(sender, "authme.admin.totpviewstatus")
                || hasAdmin(sender, "authme.admin.totpdisable"))) {
                return filter(List.of("status", "disable"), args[1]);
            }
            if ("switchantibot".equals(sub) && hasAdmin(sender, "authme.admin.switchantibot")) {
                return filter(List.of("on", "off"), args[1]);
            }
            if (targetSubcommand(sub) && rootCompletionAllowed(sender, sub)) {
                return filter(runtime.onlinePlayerNames(), args[1]);
            }
        }
        if (args.length == 3) {
            String sub = rootSubcommand(args[0]);
            if ("debug".equals(sub) && "mysqldef".equalsIgnoreCase(args[1]) && hasDebug(sender, "mysqldef")) {
                return filter(List.of("add", "remove", "details"), args[2]);
            }
            if ("email".equals(sub) && ("get".equalsIgnoreCase(args[1]) || "set".equalsIgnoreCase(args[1]))
                && hasAdmin(sender, "get".equalsIgnoreCase(args[1]) ? "authme.admin.getemail" : "authme.admin.changemail")) {
                return filter(runtime.onlinePlayerNames(), args[2]);
            }
            if ("totp".equals(sub) && ("status".equalsIgnoreCase(args[1]) || "disable".equalsIgnoreCase(args[1]))) {
                String node = "disable".equalsIgnoreCase(args[1])
                    ? "authme.admin.totpdisable" : "authme.admin.totpviewstatus";
                if (hasAdmin(sender, node)) return filter(runtime.onlinePlayerNames(), args[2]);
            }
        }
        if (args.length == 4 && "debug".equalsIgnoreCase(args[0]) && "mysqldef".equalsIgnoreCase(args[1])
            && ("add".equalsIgnoreCase(args[2]) || "remove".equalsIgnoreCase(args[2]))
            && hasDebug(sender, "mysqldef")) {
            return filter(List.of("LASTLOGIN", "LASTIP", "EMAIL"), args[3]);
        }
        return List.of();
    }

    private static boolean rootCompletionAllowed(CommandSender sender, String sub) {
        sub = rootSubcommand(sub);
        return switch (sub) {
            case "version", "help" -> true;
            case "reload" -> hasAdmin(sender, "authme.admin.reload");
            case "register" -> hasAdmin(sender, "authme.admin.register");
            case "unregister" -> hasAdmin(sender, "authme.admin.unregister");
            case "forcelogin", "auth", "unauth" -> hasAdmin(sender, "authme.admin.forcelogin");
            case "password", "setpassword" -> hasAdmin(sender, "authme.admin.changepassword");
            case "accountdata", "lastlogin" -> hasAdmin(sender, "authme.admin.lastlogin");
            case "accounts" -> (sender instanceof Player && hasPlayer(sender, "authme.player.seeownaccounts"))
                || hasAdmin(sender, "authme.admin.accounts");
            case "getip" -> hasAdmin(sender, "authme.admin.getip");
            case "email" -> hasAdmin(sender, "authme.admin.getemail");
            case "totp" -> hasAdmin(sender, "authme.admin.totpviewstatus")
                || hasAdmin(sender, "authme.admin.totpdisable");
            case "disabletotp" -> hasAdmin(sender, "authme.admin.totpdisable");
            case "premium" -> hasAdmin(sender, "authme.admin.setpremium");
            case "freemium" -> hasAdmin(sender, "authme.admin.setfreemium");
            case "recent" -> hasAdmin(sender, "authme.admin.seerecent");
            case "purge" -> hasAdmin(sender, "authme.admin.purge");
            case "resetpos" -> hasAdmin(sender, "authme.admin.purgelastpos");
            case "purgeplayer" -> hasAdmin(sender, "authme.admin.purgeplayer");
            case "purgebannedplayers" -> hasAdmin(sender, "authme.admin.purgebannedplayers");
            case "spawn" -> hasAdmin(sender, "authme.admin.spawn");
            case "setspawn" -> hasAdmin(sender, "authme.admin.setspawn");
            case "firstspawn" -> hasAdmin(sender, "authme.admin.firstspawn");
            case "setfirstspawn" -> hasAdmin(sender, "authme.admin.setfirstspawn");
            case "backup" -> hasAdmin(sender, "authme.admin.backup");
            case "converter" -> hasAdmin(sender, "authme.admin.converter");
            case "messages" -> hasAdmin(sender, "authme.admin.updatemessages");
            case "switchantibot" -> hasAdmin(sender, "authme.admin.switchantibot");
            case "debug" -> hasDebugRoot(sender);
            case "setemail" -> hasAdmin(sender, "authme.admin.changemail");
            default -> false;
        };
    }

    private static boolean targetSubcommand(String sub) {
        sub = rootSubcommand(sub);
        return List.of("register", "unregister", "forcelogin", "auth", "unauth", "password", "setpassword",
            "accountdata", "lastlogin", "getip", "accounts", "email", "premium", "freemium", "resetpos",
            "purgeplayer").contains(sub);
    }

    private static void rootHelp(CommandSender sender, String query) {
        String value = query == null ? "" : rootSubcommand(query.trim());
        if (value.isBlank()) {
            sender.sendMessage(ChatColor.YELLOW + "AuthMe: /authme version|reload|help|debug|converter|messages");
            sender.sendMessage(ChatColor.YELLOW + "Accounts: /authme register|unregister|forcelogin|password|lastlogin|accounts|getip|recent|purge|backup");
            sender.sendMessage(ChatColor.YELLOW + "Security: /authme email|setemail|totp|disabletotp|premium|freemium|switchantibot");
            sender.sendMessage(ChatColor.YELLOW + "World: /authme spawn|setspawn|firstspawn|setfirstspawn|resetpos|purgeplayer|purgebannedplayers");
            return;
        }
        String usage = switch (value) {
            case "reload" -> "/authme reload";
            case "version" -> "/authme version";
            case "register" -> "/authme register <player> <password>";
            case "unregister" -> "/authme unregister <player>";
            case "forcelogin", "auth" -> "/authme forcelogin <player>";
            case "password", "setpassword" -> "/authme password <player> <password>";
            case "lastlogin", "accountdata" -> "/authme lastlogin [player]";
            case "accounts" -> "/authme accounts [player]";
            case "getip" -> "/authme getip <player>";
            case "email" -> "/authme email [player] | /authme email get|set ...";
            case "totp" -> "/authme totp <player> | /authme totp status|disable <player>";
            case "debug" -> "/authme debug <country|db|group|limbo|mail|mysqldef|perm|spawn|stats|valid> ...";
            case "converter" -> "/authme converter list|<id> [path|table]";
            case "purge" -> "/authme purge [days]";
            case "purgeplayer" -> "/authme purgeplayer <player> [force]";
            case "recent" -> "/authme recent [limit]";
            default -> null;
        };
        sender.sendMessage(usage == null ? ChatColor.RED + "Unknown AuthMe help topic: " + query
            : ChatColor.YELLOW + "Usage: " + usage);
    }

    private static void playerHelp(CommandSender sender, String root) {
        String usage = switch (root) {
            case "login", "l" -> "/login <password>";
            case "register", "reg" -> "/register <password> [confirmation]";
            case "logout" -> "/logout";
            case "unregister" -> "/unregister <password>";
            case "changepassword", "changepass" -> "/changepassword <oldPassword> <newPassword>";
            case "2fa", "totp" -> "/totp code <code>|add|confirm <code>|remove <code>";
            case "email" -> "/email show|add|change|recover|code|confirm|setpassword ...";
            case "captcha" -> "/captcha <code>";
            case "verification" -> "/verification <code>";
            case "premium" -> "/premium";
            case "freemium" -> "/freemium";
            default -> "/" + root + " help";
        };
        sender.sendMessage(ChatColor.YELLOW + "Usage: " + usage);
    }

    private static String targetOrSender(CommandSender sender, String[] args, int index) {
        if (args.length > index) return args[index];
        return sender instanceof Player player ? player.getName() : null;
    }

    private static List<String> filter(List<String> values, String prefix) {
        String normalized = prefix == null ? "" : prefix.toLowerCase(Locale.ROOT);
        List<String> result = new ArrayList<>();
        for (String value : values) if (value.startsWith(normalized)) result.add(value);
        return result;
    }
}
