package io.github.authme.fabric.config;

import io.github.authme.fabric.util.Log;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** AuthMe-compatible event command configuration. Execution remains platform-specific. */
public final class EventCommands {

    private final Path file;
    private final Map<String, List<ConfiguredCommand>> commands = new LinkedHashMap<>();

    public EventCommands(Path configDir) {
        this.file = configDir.resolve("commands.yml");
        load();
    }

    public synchronized boolean load() {
        commands.clear();
        try {
            Files.createDirectories(file.getParent());
            if (!Files.exists(file)) {
                try (InputStream in = getClass().getResourceAsStream("/assets/authme/commands.yml")) {
                    if (in == null) return false;
                    try (OutputStream out = Files.newOutputStream(file)) { in.transferTo(out); }
                }
            }
            Object loaded;
            try (InputStream in = Files.newInputStream(file)) {
                loaded = new Yaml(new SafeConstructor(new LoaderOptions())).load(in);
            }
            if (!(loaded instanceof Map<?, ?> root)) return false;
            for (Map.Entry<?, ?> event : root.entrySet()) {
                if (event.getKey() == null || !(event.getValue() instanceof Map<?, ?> entries)) continue;
                List<ConfiguredCommand> parsed = new ArrayList<>();
                for (Map.Entry<?, ?> entry : entries.entrySet()) {
                    if (!(entry.getValue() instanceof Map<?, ?> value)) continue;
                    String command = string(value.get("command"), "").trim();
                    if (command.isEmpty()) continue;
                    Executor executor = Executor.parse(string(value.get("executor"), "CONSOLE"));
                    int delay = Math.max(0, integer(value.get("delay"), 0));
                    int atLeast = integer(value.get("ifNumberOfAccountsAtLeast"), -1);
                    int lessThan = integer(value.get("ifNumberOfAccountsLessThan"), -1);
                    parsed.add(new ConfiguredCommand(command, executor, delay, atLeast, lessThan));
                }
                commands.put(String.valueOf(event.getKey()), List.copyOf(parsed));
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
        List<ConfiguredCommand> result = commands.get(event);
        if (result == null) result = commands.get(event.toLowerCase(Locale.ROOT));
        return result == null ? Collections.emptyList() : result;
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
