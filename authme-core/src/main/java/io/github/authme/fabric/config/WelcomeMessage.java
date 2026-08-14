package io.github.authme.fabric.config;

import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/** Loads and renders AuthMeReloaded's optional welcome.txt file without platform dependencies. */
public final class WelcomeMessage {

    private WelcomeMessage() {
    }

    public static List<String> load(AuthMeConfig config) {
        if (config == null || !config.welcomeEnabled()) return List.of();
        try {
            if (!Files.exists(config.welcomeFile())) return List.of();
            return new ArrayList<>(Files.readAllLines(config.welcomeFile()));
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
