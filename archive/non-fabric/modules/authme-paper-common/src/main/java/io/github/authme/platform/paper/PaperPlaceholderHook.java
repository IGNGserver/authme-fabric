package io.github.authme.platform.paper;

import me.clip.placeholderapi.expansion.PlaceholderExpansion;
import org.bukkit.OfflinePlayer;
import org.bukkit.plugin.java.JavaPlugin;

/**
 * Optional PlaceholderAPI adapter. This class is loaded only after the plugin manager reports
 * PlaceholderAPI as enabled, so servers without PlaceholderAPI do not need its classes at runtime.
 */
public final class PaperPlaceholderHook {

    private PaperPlaceholderHook() { }

    public static Object register(JavaPlugin plugin, PaperAuthRuntime runtime) {
        if (!plugin.getServer().getPluginManager().isPluginEnabled("PlaceholderAPI")) return null;
        AuthMeExpansion expansion = new AuthMeExpansion(runtime, plugin.getDescription().getVersion());
        return expansion.register() ? expansion : null;
    }

    public static void unregister(Object expansion) {
        if (expansion instanceof AuthMeExpansion authMeExpansion) authMeExpansion.unregister();
    }

    private static final class AuthMeExpansion extends PlaceholderExpansion {
        private final PaperAuthRuntime runtime;
        private final String version;

        private AuthMeExpansion(PaperAuthRuntime runtime, String version) {
            this.runtime = runtime;
            this.version = version == null || version.isBlank() ? "unknown" : version;
        }

        @Override
        public String getIdentifier() { return "authme"; }

        @Override
        public String getAuthor() { return "AuthMe"; }

        @Override
        public String getVersion() { return version; }

        @Override
        public boolean persist() { return true; }

        @Override
        public String onRequest(OfflinePlayer player, String params) {
            String key = params == null ? "" : params.trim().toLowerCase(java.util.Locale.ROOT);
            if ("version".equals(key)) return version;
            if (player == null) return "";
            org.bukkit.entity.Player online = player.getPlayer();
            if (online == null) return "";
            return switch (key) {
                case "is_logged_in", "logged_in", "authenticated" ->
                    Boolean.toString(runtime.isAuthenticated(online));
                case "is_registered", "registered" -> Boolean.toString(runtime.isRegistered(online));
                case "is_unrestricted", "unrestricted" -> Boolean.toString(runtime.isUnrestricted(online));
                case "is_npc", "npc" -> Boolean.toString(runtime.isNpc(online));
                case "status" -> runtime.placeholderStatus(online);
                default -> null;
            };
        }
    }
}
