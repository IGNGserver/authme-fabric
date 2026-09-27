package io.github.authme.fabric.converter;

import io.github.authme.fabric.util.Log;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Registry of built-in {@link Converter}s. Add new converters here so they appear in
 * {@code /authme converter list} automatically.
 */
public final class Converters {

    private Converters() {
    }

    private static final Map<String, ConverterFactory> REGISTRY = new LinkedHashMap<>();

    static {
        register("sqlitetosql", SQLiteToSqlConverter::new);
        register("authplus", args -> new PluginImportConverter("authplus",
            "Import Auth+ players.yml (entries must contain a player name and password hash).",
            "plugins/Auth/players.yml", "", true).withArgument(args));
        register("librelogin", args -> new PluginImportConverter("librelogin",
            "Import LibreLogin SQLite account rows; use path or path|table.",
            "plugins/LibreLogin/user-data.db", "librepremium_data").withArgument(args));
        register("limboauth", args -> new PluginImportConverter("limboauth",
            "Import LimboAuth SQLite account rows; use path or path|table.",
            "plugins/LimboAuth/database.db", "users").withArgument(args));
        register("nlogin", args -> new PluginImportConverter("nlogin",
            "Import nLogin SQLite account rows; use path or path|table.",
            "plugins/nLogin/nlogin.db", "nlogin").withArgument(args));
        register("openlogin", args -> new PluginImportConverter("openlogin",
            "Import OpeNLogin SQLite account rows; use path or path|table.",
            "plugins/OpeNLogin/accounts.db", "openlogin").withArgument(args));
        register("tiauth", args -> new PluginImportConverter("tiauth",
            "Import tiAuth SQLite account rows; use path or path|table.",
            "plugins/tiAuth/auth.db", "auth_users").withArgument(args));
        register("nexauth", args -> new PluginImportConverter("nexauth",
            "Import NexAuth SQLite account rows; use path or path|table.",
            "plugins/NexAuth/user-data.db", "librepremium_data").withArgument(args));
        register("mysqltosqlite", args -> new PluginImportConverter("mysqltosqlite",
            "Import an AuthMe-shaped SQLite snapshot into the active SQLite target; use path or path|table.",
            "authme.db", "authme").withArgument(args));
    }

    /** A factory that builds a converter from a free-form string argument (path / connection / ...). */
    @FunctionalInterface
    public interface ConverterFactory {
        Converter build(String argument) throws Exception;
    }

    public static void register(String id, ConverterFactory factory) {
        REGISTRY.put(id.toLowerCase(java.util.Locale.ROOT), factory);
    }

    /** @return a lowercase-id → description listing usable for command help. */
    public static String listing() {
        StringBuilder sb = new StringBuilder();
        for (String id : REGISTRY.keySet()) {
            ConverterFactory f = REGISTRY.get(id);
            try {
                Converter c = f.build(null);
                sb.append("&a").append(id).append("&7 - ").append(c.description()).append('\n');
            } catch (Exception ignored) {
                sb.append("&a").append(id).append("&7 - (failed to describe)\n");
            }
        }
        return sb.toString();
    }

    /** Stable converter IDs for native command completion. */
    public static List<String> ids() {
        return List.copyOf(REGISTRY.keySet());
    }

    /**
     * @return a built converter for the given id, or {@code null} if unknown.
     */
    public static Converter build(String id, String argument) {
        ConverterFactory f = REGISTRY.get(id.toLowerCase(java.util.Locale.ROOT));
        if (f == null) return null;
        try {
            return f.build(argument);
        } catch (Exception e) {
            Log.error("Could not build converter '" + id + "'", e);
            return null;
        }
    }

    public static boolean isRegistered(String id) {
        return REGISTRY.containsKey(id.toLowerCase(java.util.Locale.ROOT));
    }

}
