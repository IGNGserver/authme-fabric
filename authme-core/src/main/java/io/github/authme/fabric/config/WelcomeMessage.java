package io.github.authme.fabric.config;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Loads and renders AuthMeReloaded's optional welcome.txt file without platform dependencies. */
public final class WelcomeMessage {

    private static final long MAX_FILE_BYTES = 256 * 1024L;
    private static final int MAX_LINES = 256;

    private WelcomeMessage() {
    }

    public static List<String> load(AuthMeConfig config) {
        if (config == null || !config.welcomeEnabled()) return List.of();
        Path file = config.welcomeFile();
        try {
            if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(file) || Files.size(file) > MAX_FILE_BYTES) return List.of();
            List<String> lines = new ArrayList<>();
            try (InputStream input = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS);
                 BufferedReader reader = new BufferedReader(new InputStreamReader(
                     input, StandardCharsets.UTF_8))) {
                String line;
                while (lines.size() < MAX_LINES && (line = reader.readLine()) != null) {
                    lines.add(line);
                }
            }
            return lines;
        } catch (IOException | RuntimeException ignored) {
            return List.of();
        }
    }

    public static String render(String value, String player, String ip, int online, int maxPlayers,
                                String world, String serverName, int loggedIn, String country) {
        if (value == null) return "";
        return value.replace("{PLAYER}", safe(player))
            .replace("{ONLINE}", Integer.toString(online))
            .replace("{MAXPLAYERS}", Integer.toString(maxPlayers))
            .replace("{IP}", safe(ip))
            .replace("{WORLD}", safe(world))
            .replace("{SERVER}", safe(serverName))
            .replace("{LOGINS}", Integer.toString(loggedIn))
            .replace("{COUNTRY}", safe(country));
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
