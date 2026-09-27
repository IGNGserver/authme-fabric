package io.github.authme.fabric.config;

import io.github.authme.fabric.util.Log;
import io.github.authme.fabric.util.SecureFileAccess;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** AuthMe-compatible event command configuration. Execution remains platform-specific. */
public final class EventCommands {

    private static final int MAX_COMMANDS_PER_EVENT = 256;
    private static final int MAX_COMMAND_LENGTH = 512;
    private static final int MAX_DELAY_TICKS = 20 * 86_400;
    private static final java.util.Set<String> EVENTS = java.util.Set.of(
        "onjoin", "onlogin", "onsessionlogin", "onfirstlogin", "onregister", "onunregister", "onlogout");

    private final Path file;
    private final Map<String, List<ConfiguredCommand>> commands = new LinkedHashMap<>();

    public EventCommands(Path configDir) {
        this.file = configDir.resolve("commands.yml");
        load();
    }

    public synchronized boolean load() {
        commands.clear();
        try {
            SecureFileAccess.ensurePrivateDirectory(file.getParent());
            if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
                try (InputStream in = getClass().getResourceAsStream("/assets/authme/commands.yml")) {
                    if (in == null) return false;
                    try (OutputStream out = SecureFileAccess.createNewPrivateFile(file)) {
                        in.transferTo(out);
                    }
                }
            } else {
                SecureFileAccess.harden(file);
            }
            Object loaded;
            try (InputStream in = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
                LoaderOptions options = new LoaderOptions();
                options.setCodePointLimit(256 * 1024);
                options.setMaxAliasesForCollections(16);
                options.setNestingDepthLimit(32);
                loaded = new Yaml(new SafeConstructor(options)).load(in);
            }
            if (!(loaded instanceof Map<?, ?> root)) return false;
            for (Map.Entry<?, ?> event : root.entrySet()) {
                if (event.getKey() == null || !(event.getValue() instanceof Map<?, ?> entries)) continue;
                String eventName = String.valueOf(event.getKey()).trim().toLowerCase(Locale.ROOT);
                if (!EVENTS.contains(eventName)) continue;
                List<ConfiguredCommand> parsed = new ArrayList<>();
                for (Map.Entry<?, ?> entry : entries.entrySet()) {
                    if (parsed.size() >= MAX_COMMANDS_PER_EVENT) break;
                    if (!(entry.getValue() instanceof Map<?, ?> value)) continue;
                    String command = string(value.get("command"), "").trim();
                    if (command.isEmpty() || command.length() > MAX_COMMAND_LENGTH) continue;
                    Executor executor = Executor.parse(string(value.get("executor"), "CONSOLE"));
                    int delay = Math.min(MAX_DELAY_TICKS, Math.max(0, integer(value.get("delay"), 0)));
                    int atLeast = boundedAccountLimit(integer(value.get("ifNumberOfAccountsAtLeast"), -1));
                    int lessThan = boundedAccountLimit(integer(value.get("ifNumberOfAccountsLessThan"), -1));
                    parsed.add(new ConfiguredCommand(command, executor, delay, atLeast, lessThan));
                }
                commands.put(eventName, List.copyOf(parsed));
            }
            return true;
        } catch (IOException | RuntimeException e) {
            Log.error("Could not load commands.yml", e);
            commands.clear();
            return false;
        }
    }

    public synchronized List<ConfiguredCommand> get(String event) {
        if (event == null) return Collections.emptyList();
        List<ConfiguredCommand> result = commands.get(event.trim().toLowerCase(Locale.ROOT));
        return result == null ? Collections.emptyList() : result;
    }

    private static int boundedAccountLimit(int value) {
        return value < 0 ? -1 : Math.min(10_000, value);
    }

    private static String string(Object value, String fallback) {
        return value == null ? fallback : String.valueOf(value);
    }

    private static int integer(Object value, int fallback) {
        if (value instanceof Number n) return n.intValue();
        if (value instanceof String s) {
            try { return Integer.parseInt(s.trim()); } catch (NumberFormatException ignored) { }
        }
        return fallback;
    }

    public record ConfiguredCommand(String command, Executor executor, int delayTicks,
                                    int accountsAtLeast, int accountsLessThan) { }

    public enum Executor {
        CONSOLE, PLAYER;

        static Executor parse(String value) {
            try { return valueOf(value.toUpperCase(Locale.ROOT)); }
            catch (IllegalArgumentException e) { return CONSOLE; }
        }
    }
}
