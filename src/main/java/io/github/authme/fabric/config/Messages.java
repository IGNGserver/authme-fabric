package io.github.authme.fabric.config;

import io.github.authme.fabric.util.Log;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.LoaderOptions;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Loads {@code messages.yml} (and optional {@code messages_<locale>.yml} overrides) and provides
 * lookup with placeholder replacement.
 */
public final class Messages {

    private final Path configDir;
    private final Map<String, String> messages = new HashMap<>();
    private final Map<String, String> overrides = new HashMap<>();

    public Messages(Path configDir) {
        this.configDir = configDir;
    }

    public boolean load() {
        messages.clear();
        try {
            Files.createDirectories(configDir);
            Path file = configDir.resolve("messages.yml");
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
            loadInto(file);
            return true;
        } catch (IOException | RuntimeException e) {
            Log.error("Could not load messages.yml", e);
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private void loadInto(Path file) throws IOException {
        if (!Files.exists(file)) return;
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        try (InputStream in = Files.newInputStream(file)) {
            Object loaded = yaml.load(in);
            if (loaded instanceof Map<?, ?> map) {
                for (Map.Entry<?, ?> e : map.entrySet()) {
                    if (e.getKey() == null) continue;
                    String key = String.valueOf(e.getKey());
                    String value = e.getValue() == null ? "" : String.valueOf(e.getValue());
                    messages.put(key, value);
                }
            }
        }
    }

    /**
     * @return the localized message, with placeholder pairs (name, value, name, value, ...)
     *         replaced as {@code {name}}.
     */
    public String get(String key, Object... replacements) {
        String raw = messages.get(key);
        if (raw == null) raw = overrides.get(key);
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
        return messages.containsKey(key);
    }
}