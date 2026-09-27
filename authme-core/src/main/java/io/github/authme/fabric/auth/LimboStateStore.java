package io.github.authme.fabric.auth;

import io.github.authme.fabric.util.Log;
import io.github.authme.fabric.util.SecureFileAccess;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Properties;
import java.util.UUID;

/**
 * Crash-safe persistence for the small set of player properties temporarily
 * changed while a player is unauthenticated.  This is deliberately separate
 * from the AuthMe account table: limbo state is server-local and must never be
 * copied between servers sharing an account database.
 */
public final class LimboStateStore {

    public enum Persistence {
        DISABLED,
        INDIVIDUAL_FILES,
        DISTRIBUTED_FILES;

        public static Persistence parse(String value) {
            if (value == null) return INDIVIDUAL_FILES;
            try {
                return valueOf(value.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException ignored) {
                return INDIVIDUAL_FILES;
            }
        }
    }

    public record State(boolean operator, boolean mayFly, boolean flying,
                        float walkingSpeed, float flyingSpeed, boolean invulnerable) {
    }

    private final Path directory;
    private final Persistence persistence;
    private final int distributionBuckets;

    public LimboStateStore(Path configDir, String configuredPersistence) {
        this(configDir, configuredPersistence, "SIXTEEN");
    }

    public LimboStateStore(Path configDir, String configuredPersistence, String configuredDistributionSize) {
        this.persistence = Persistence.parse(configuredPersistence);
        this.directory = configDir.resolve("limbo");
        this.distributionBuckets = parseDistributionBuckets(configuredDistributionSize);
    }

    public Persistence persistence() {
        return persistence;
    }

    public synchronized State load(UUID uuid) {
        Path file = fileFor(uuid);
        if (file == null || uuid == null || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) return null;
        Properties properties = read(file);
        if (properties == null) return null;
        String prefix = prefix(uuid);
        try {
            String marker = properties.getProperty(prefix + "present");
            if (!"true".equalsIgnoreCase(marker)) return null;
            return new State(
                bool(properties, prefix + "operator"),
                bool(properties, prefix + "mayFly"),
                bool(properties, prefix + "flying"),
                number(properties, prefix + "walkingSpeed", 0.1f),
                number(properties, prefix + "flyingSpeed", 0.05f),
                bool(properties, prefix + "invulnerable"));
        } catch (RuntimeException e) {
            Log.warn("Ignoring invalid AuthMe limbo state for " + uuid, e);
            return null;
        }
    }

    public synchronized boolean save(UUID uuid, State state) {
        Path file = fileFor(uuid);
        if (file == null || uuid == null || state == null) return true;
        Properties properties = read(file);
        if (properties == null) properties = new Properties();
        String prefix = prefix(uuid);
        properties.setProperty(prefix + "present", "true");
        properties.setProperty(prefix + "operator", Boolean.toString(state.operator()));
        properties.setProperty(prefix + "mayFly", Boolean.toString(state.mayFly()));
        properties.setProperty(prefix + "flying", Boolean.toString(state.flying()));
        properties.setProperty(prefix + "walkingSpeed", Float.toString(state.walkingSpeed()));
        properties.setProperty(prefix + "flyingSpeed", Float.toString(state.flyingSpeed()));
        properties.setProperty(prefix + "invulnerable", Boolean.toString(state.invulnerable()));
        return write(file, properties);
    }

    public synchronized boolean remove(UUID uuid) {
        Path file = fileFor(uuid);
        if (file == null || uuid == null || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) return true;
        if (Files.isSymbolicLink(file)) return false;
        if (persistence == Persistence.INDIVIDUAL_FILES) {
            try {
                Files.deleteIfExists(file);
                return true;
            } catch (IOException e) {
                Log.warn("Could not remove AuthMe limbo state for " + uuid, e);
                return false;
            }
        }
        Properties properties = read(file);
        if (properties == null) return false;
        String prefix = prefix(uuid);
        for (String key : java.util.List.copyOf(properties.stringPropertyNames())) {
            if (key.startsWith(prefix)) properties.remove(key);
        }
        if (properties.isEmpty()) {
            try {
                Files.deleteIfExists(file);
                return true;
            } catch (IOException e) {
                Log.warn("Could not remove AuthMe limbo bucket for " + uuid, e);
                return false;
            }
        }
        return write(file, properties);
    }

    private Path fileFor(UUID uuid) {
        if (persistence == Persistence.DISABLED || uuid == null) return null;
        try {
            SecureFileAccess.ensurePrivateDirectory(directory);
        } catch (IOException e) {
            Log.warn("Could not create AuthMe limbo directory " + directory, e);
            return null;
        }
        if (persistence == Persistence.INDIVIDUAL_FILES) {
            return directory.resolve(uuid + ".properties");
        }
        int bucket = Math.floorMod(uuid.hashCode(), distributionBuckets);
        return directory.resolve(String.format(Locale.ROOT, "bucket-%03d.properties", bucket));
    }

    private static String prefix(UUID uuid) {
        return uuid + ".";
    }

    private static Properties read(Path file) {
        Properties properties = new Properties();
        try {
            SecureFileAccess.harden(file);
            try (InputStream in = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
                properties.load(in);
                return properties;
            }
        } catch (IOException e) {
            if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
                Log.warn("Could not read AuthMe limbo state " + file, e);
            }
            return null;
        }
    }

    private static boolean write(Path file, Properties properties) {
        Path temporary = null;
        try {
            Path parent = file.toAbsolutePath().normalize().getParent();
            SecureFileAccess.ensurePrivateDirectory(parent);
            if (Files.isSymbolicLink(file)) return false;
            temporary = SecureFileAccess.createPrivateTempFile(parent,
                file.getFileName() + ".", ".tmp");
            try (OutputStream out = Files.newOutputStream(temporary, LinkOption.NOFOLLOW_LINKS)) {
                properties.store(out, "AuthMe limbo state; do not edit while the server is running");
            }
            SecureFileAccess.replace(temporary, file);
            temporary = null;
            return true;
        } catch (IOException | RuntimeException e) {
            Log.warn("Could not write AuthMe limbo state " + file, e);
            if (temporary != null) {
                try { Files.deleteIfExists(temporary); } catch (IOException ignored) { }
            }
            return false;
        }
    }

    private static boolean bool(Properties properties, String key) {
        return Boolean.parseBoolean(properties.getProperty(key, "false"));
    }

    private static float number(Properties properties, String key, float fallback) {
        try {
            float value = Float.parseFloat(properties.getProperty(key, Float.toString(fallback)));
            return Float.isFinite(value) && value >= 0.0f && value <= 10.0f ? value : fallback;
        } catch (NumberFormatException e) { return fallback; }
    }

    private static int parseDistributionBuckets(String value) {
        if (value == null) return 16;
        return switch (value.trim().toUpperCase(Locale.ROOT)) {
            case "ONE" -> 1;
            case "FOUR" -> 4;
            case "EIGHT" -> 8;
            case "SIXTEEN" -> 16;
            case "THIRTY_TWO" -> 32;
            case "SIXTY_FOUR" -> 64;
            case "ONE_TWENTY", "ONE_HUNDRED_TWENTY_EIGHT", "128" -> 128;
            case "TWO_FIFTY", "TWO_HUNDRED_FIFTY_SIX", "256" -> 256;
            default -> {
                try {
                    int parsed = Integer.parseInt(value.trim());
                    yield parsed == 1 || parsed == 4 || parsed == 8 || parsed == 16
                        || parsed == 32 || parsed == 64 || parsed == 128 || parsed == 256 ? parsed : 16;
                } catch (NumberFormatException ignored) {
                    yield 16;
                }
            }
        };
    }
}
