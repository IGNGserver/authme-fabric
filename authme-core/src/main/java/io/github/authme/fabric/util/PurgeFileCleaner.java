package io.github.authme.fabric.util;

import io.github.authme.fabric.config.AuthMeConfig;
import io.github.authme.fabric.datasource.PlayerAuth;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.stream.Stream;

/**
 * Safely removes the optional files covered by AuthMeReloaded's Purge settings.
 * Every target is derived from a validated UUID/name and remains below the
 * server root; all switches default to false.
 */
public final class PurgeFileCleaner {

    private PurgeFileCleaner() { }

    public static int clean(Path serverRoot, AuthMeConfig config, List<PlayerAuth> accounts,
                            boolean onlineMode) {
        if (serverRoot == null || config == null || accounts == null || accounts.isEmpty()) return 0;
        Path root = serverRoot.toAbsolutePath().normalize();
        int deleted = 0;
        for (PlayerAuth account : accounts) {
            if (account == null) continue;
            UUID uuid = account.getUuid();
            if (uuid == null && !onlineMode) uuid = offlineUuid(account.getRealName(), account.getName());
            if (config.purgeRemovePlayerDat() && uuid != null) {
                Path world = safeWorld(root, config.purgeDefaultWorld());
                deleted += deletePath(world.resolve("playerdata").resolve(uuid + ".dat"), root);
                // AuthMe's Bukkit implementation historically used world/players.
                deleted += deletePath(world.resolve("players").resolve(uuid + ".dat"), root);
            }
            if (uuid != null && config.purgeRemoveEssentialsFile()) {
                deleted += deleteBelow(root, "plugins", "Essentials", "userdata", uuid + ".yml");
            }
            if (config.purgeRemoveLimitedCreativeInventories()) {
                deleted += deleteLimitedCreative(root, safeName(account.getName()));
            }
            if (config.purgeRemoveAntiXrayFile()) {
                deleted += deleteBelow(root, "plugins", "AntiXRayData", "PlayerData", safeName(account.getName()));
            }
            if (config.purgeRemovePermissions() && uuid != null) {
                Boolean cleared = PermissionBridge.clearGroups(uuid);
                if (Boolean.FALSE.equals(cleared)) {
                    Log.warn("Could not clear permission groups for purged account " + account.getName());
                }
            }
        }
        return deleted;
    }

    private static int deleteLimitedCreative(Path root, String name) {
        if (name == null) return 0;
        Path folder = resolveBelow(root, "plugins", "LimitedCreative", "inventories");
        if (folder == null || !Files.isDirectory(folder)) return 0;
        int deleted = 0;
        try (Stream<Path> files = Files.list(folder)) {
            for (Path path : files.toList()) {
                String filename = path.getFileName().toString();
                String lower = filename.toLowerCase(Locale.ROOT);
                if (!lower.endsWith(".yml")) continue;
                String base = filename.substring(0, filename.length() - 4);
                String baseLower = base.toLowerCase(Locale.ROOT);
                String plain = baseLower;
                for (String suffix : List.of("_creative", "_adventure", "_survival")) {
                    if (plain.endsWith(suffix)) plain = plain.substring(0, plain.length() - suffix.length());
                }
                if (plain.equals(name.toLowerCase(Locale.ROOT)) && deleteExact(path, root)) deleted++;
            }
        } catch (IOException e) {
            Log.warn("Could not inspect LimitedCreative purge directory: " + e.getMessage());
        }
        return deleted;
    }

    private static int deleteBelow(Path root, String... parts) {
        Path path = resolveBelow(root, parts);
        return deletePath(path, root);
    }

    private static int deletePath(Path path, Path root) {
        return path != null && deleteExact(path.normalize(), root) ? 1 : 0;
    }

    private static boolean deleteExact(Path path, Path root) {
        try {
            Path absoluteRoot = root.toAbsolutePath().normalize();
            Path normalized = path.toAbsolutePath().normalize();
            if (!normalized.startsWith(absoluteRoot)
                || !Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)) return false;

            // A lexical startsWith check is not enough: a server-owned directory may be a
            // symlink to a path outside the server root. Resolve the parent directory before
            // deleting, and never follow a symlink at the final file component.
            Path realRoot = absoluteRoot.toRealPath();
            Path parent = normalized.getParent();
            if (parent == null || !parent.toRealPath().startsWith(realRoot)) return false;
            return Files.deleteIfExists(normalized);
        } catch (IOException e) {
            Log.warn("Could not remove purge file " + path + ": " + e.getMessage());
            return false;
        }
    }

    private static Path safeWorld(Path root, String configured) {
        if (configured == null || configured.isBlank()) return root.resolve("world");
        Path value;
        try { value = Path.of(configured); } catch (RuntimeException e) { return root.resolve("world"); }
        if (value.isAbsolute() || value.getNameCount() != 1 || configured.equals(".") || configured.equals("..")) {
            Log.warn("Ignoring unsafe Purge.defaultWorld path: " + configured);
            return root.resolve("world");
        }
        return root.resolve(value).normalize();
    }

    private static Path resolveBelow(Path root, String... parts) {
        Path path = root;
        for (String part : parts) {
            if (part == null || part.isBlank() || part.equals(".") || part.equals("..")
                || part.contains("\\") || part.contains("/")) return null;
            path = path.resolve(part);
        }
        path = path.normalize();
        return path.startsWith(root) ? path : null;
    }

    private static String safeName(String name) {
        if (name == null || name.isBlank() || name.length() > 16) return null;
        return name.matches("[A-Za-z0-9_-]+") ? name : null;
    }

    private static UUID offlineUuid(String realName, String storedName) {
        String name = realName == null || realName.isBlank() ? storedName : realName;
        if (name == null || name.isBlank()) return null;
        return UUID.nameUUIDFromBytes(("OfflinePlayer:" + name).getBytes(StandardCharsets.UTF_8));
    }
}
