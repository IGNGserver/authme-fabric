package io.github.authme.fabric.converter;

import io.github.authme.fabric.util.Log;

import java.util.LinkedHashMap;
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
        // Stub converters — listed for awareness, will report "not implemented" when run.
        register("authplus",       args -> stub("authplus", args));
        register("librelogin",     args -> stub("librelogin", args));
        register("limboauth",      args -> stub("limboauth", args));
        register("nlogin",         args -> stub("nlogin", args));
        register("openlogin",      args -> stub("openlogin", args));
        register("tiauth",         args -> stub("tiauth", args));
        register("nexauth",        args -> stub("nexauth", args));
        register("mysqltosqlite",  args -> stub("mysqltosqlite", args));
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

    private static Converter stub(String id, String arg) {
        return new StubConverter(id, "Not implemented in this Fabric port yet. Tracked as a known limitation.");
    }
}