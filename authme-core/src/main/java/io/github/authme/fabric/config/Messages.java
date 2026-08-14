package io.github.authme.fabric.config;

import io.github.authme.fabric.util.Log;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.LoaderOptions;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Locale;

/**
 * Loads {@code messages.yml} (and optional {@code messages_<locale>.yml} overrides) and provides
 * lookup with placeholder replacement.
 */
public final class Messages {

    private final Path configDir;
    private final String language;
    private final Map<String, String> defaults = new LinkedHashMap<>();
    private final Map<String, String> messages = new HashMap<>();
    private final Map<String, String> overrides = new HashMap<>();

    public Messages(Path configDir) {
        this(configDir, Locale.getDefault().getLanguage());
    }

    /**
     * Loads the server-wide AuthMe message language. AuthMeReloaded stores modern language files
     * as nested YAML maps (for example {@code login.success}), while older/custom files often use
     * already flattened dotted keys; both forms are accepted here.
     */
    public Messages(Path configDir, String language) {
        this.configDir = configDir;
        this.language = normaliseLanguage(language);
    }

    public boolean load() {
        defaults.clear();
        messages.clear();
        overrides.clear();
        try {
            Files.createDirectories(configDir);
            Path file = configDir.resolve("messages.yml");
            boolean defaultsLoaded;
            try (InputStream defaults = getClass().getResourceAsStream("/assets/authme/messages.yml")) {
                defaultsLoaded = defaults != null && loadStream(defaults, this.defaults);
            }
            messages.putAll(this.defaults);
            if (!Files.exists(file)) {
                try (InputStream in = getClass().getResourceAsStream("/assets/authme/messages.yml")) {
                    if (in != null) {
                        try (OutputStream out = Files.newOutputStream(file)) {
                            in.transferTo(out);
                        }
                        Log.info("Created default messages.yml");
                    }
                }
            }
            if (!defaultsLoaded || !loadInto(file) || messages.isEmpty()) {
                Log.error("messages.yml is missing or does not contain a YAML mapping");
                return false;
            }
            if (!language.isEmpty() && !"default".equals(language)) {
                Path localeFile = configDir.resolve("messages_" + language + ".yml");
                if (Files.exists(localeFile) && !loadInto(localeFile, overrides)) {
                    Log.warn("Ignoring invalid AuthMe locale message file: " + localeFile);
                }
            }
            return true;
        } catch (IOException | RuntimeException e) {
            Log.error("Could not load messages.yml", e);
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private boolean loadInto(Path file) throws IOException {
        if (!Files.exists(file)) return false;
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        try (InputStream in = Files.newInputStream(file)) {
            return loadMap(yaml.load(in), messages);
        }
    }

    private boolean loadInto(Path file, Map<String, String> target) throws IOException {
        if (!Files.exists(file)) return false;
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        try (InputStream in = Files.newInputStream(file)) {
            return loadMap(yaml.load(in), target);
        }
    }

    private boolean loadStream(InputStream input) {
        return loadStream(input, messages);
    }

    private boolean loadStream(InputStream input, Map<String, String> target) {
        Object loaded = new Yaml(new SafeConstructor(new LoaderOptions())).load(input);
        return loadMap(loaded, target);
    }

    /**
     * Appends keys introduced by newer AuthMe versions to the user's message file.
     * Existing values are never overwritten, so custom translations remain intact.
     *
     * @return number of keys added, or {@code -1} when the file could not be updated
     */
    public int addMissingDefaults() {
        Path file = configDir.resolve("messages.yml");
        try {
            Map<String, String> current = new LinkedHashMap<>();
            if (Files.exists(file)) {
                if (!loadInto(file, current)) return -1;
            } else {
                Files.createDirectories(configDir);
            }
            List<Map.Entry<String, String>> missing = defaults.entrySet().stream()
                .filter(entry -> !current.containsKey(entry.getKey()))
                .toList();
            if (missing.isEmpty()) return 0;

            String existing = Files.exists(file) ? Files.readString(file, StandardCharsets.UTF_8) : "";
            StringBuilder addition = new StringBuilder(existing);
            if (!addition.isEmpty() && addition.charAt(addition.length() - 1) != '\n') addition.append('\n');
            addition.append("\n# Added by /authme messages; review and customise these values.\n");
            for (Map.Entry<String, String> entry : missing) {
                addition.append(entry.getKey()).append(": '")
                    .append(entry.getValue().replace("'", "''"))
                    .append("'\n");
                messages.put(entry.getKey(), entry.getValue());
            }
            Files.writeString(file, addition, StandardCharsets.UTF_8);
            return missing.size();
        } catch (IOException | RuntimeException e) {
            Log.error("Could not add missing AuthMe messages", e);
            return -1;
        }
    }

    private boolean loadMap(Object loaded, Map<String, String> target) {
        if (!(loaded instanceof Map<?, ?> map) || map.isEmpty()) return false;
        flattenMap(map, "", target);
        return true;
    }

    private static void flattenMap(Map<?, ?> map, String prefix, Map<String, String> target) {
        for (Map.Entry<?, ?> e : map.entrySet()) {
            if (e.getKey() == null) continue;
            String key = String.valueOf(e.getKey()).trim();
            if (key.isEmpty()) continue;
            String fullKey = prefix.isEmpty() ? key : prefix + "." + key;
            Object value = e.getValue();
            if (value instanceof Map<?, ?> nested) {
                flattenMap(nested, fullKey, target);
            } else {
                target.put(fullKey, value == null ? "" : String.valueOf(value));
            }
        }
    }

    private static String normaliseLanguage(String value) {
        if (value == null) return "";
        String language = value.trim().toLowerCase(Locale.ROOT).replace('-', '_');
        if (!language.matches("[a-z]{2,3}(?:_[a-z]{2,4})?")) return "";
        return language;
    }

    /**
     * @return the localized message, with placeholder pairs (name, value, name, value, ...)
     *         replaced as {@code {name}}.
     */
    public String get(String key, Object... replacements) {
        String raw = overrides.get(key);
        if (raw == null) raw = messages.get(key);
        if (raw == null) {
            return "&c[missing message: " + key + "]";
        }
        if (replacements != null && replacements.length > 0) {
            for (int i = 0; i + 1 < replacements.length; i += 2) {
                String name = String.valueOf(replacements[i]);
                String value = replacements[i + 1] == null ? "" : String.valueOf(replacements[i + 1]);
                raw = raw.replace("{" + name + "}", value);
            }
        }
        return raw;
    }

    public boolean has(String key) {
        return overrides.containsKey(key) || messages.containsKey(key);
    }
}
