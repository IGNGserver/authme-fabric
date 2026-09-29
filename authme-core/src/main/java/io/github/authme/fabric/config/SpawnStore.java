package io.github.authme.fabric.config;

import io.github.authme.fabric.util.Log;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Map;

/** Small atomic YAML store for the two AuthMe administrator spawn locations. */
public final class SpawnStore {

    private static final int MAX_YAML_CODE_POINTS = 64 * 1024;

    private final Path file;
    private final Map<String, Object> root = new LinkedHashMap<>();

    public SpawnStore(Path configDir) {
        this.file = configDir.resolve("spawn.yml");
        load();
    }

    public synchronized SpawnLocation get(String name) {
        Object value = root.get(name);
        if (!(value instanceof Map<?, ?> map)) return null;
        try {
            return new SpawnLocation(
                string(map.get("world"), "minecraft:overworld"),
                number(map.get("x"), 0.0), number(map.get("y"), 64.0), number(map.get("z"), 0.0),
                (float) number(map.get("yaw"), 0.0), (float) number(map.get("pitch"), 0.0));
        } catch (RuntimeException e) {
            Log.warn("Ignoring invalid AuthMe spawn entry '" + name + "': " + e.getMessage());
            return null;
        }
    }

    public synchronized boolean set(String name, SpawnLocation location) {
        if (name == null || name.isBlank() || location == null) return false;
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("world", location.world());
        value.put("x", location.x());
        value.put("y", location.y());
        value.put("z", location.z());
        value.put("yaw", location.yaw());
        value.put("pitch", location.pitch());
        root.put(name, value);
        return save();
    }

    private void load() {
        if (!Files.exists(file)) return;
        try (InputStream in = Files.newInputStream(file)) {
            LoaderOptions options = new LoaderOptions();
            options.setCodePointLimit(MAX_YAML_CODE_POINTS);
            options.setMaxAliasesForCollections(8);
            options.setNestingDepthLimit(16);
            Object loaded = new Yaml(new SafeConstructor(options)).load(in);
            if (loaded instanceof Map<?, ?> map) {
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (entry.getKey() != null) root.put(String.valueOf(entry.getKey()), entry.getValue());
                }
            } else {
                Log.warn("spawn.yml has an invalid root; it will be replaced when a spawn is set");
            }
        } catch (IOException | RuntimeException e) {
            Log.error("Could not load spawn.yml", e);
        }
    }

    private boolean save() {
        try {
            Files.createDirectories(file.getParent());
            Path temporary = file.resolveSibling(file.getFileName() + ".tmp");
            DumperOptions options = new DumperOptions();
            options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            options.setPrettyFlow(true);
            try (Writer writer = Files.newBufferedWriter(temporary)) {
                new Yaml(options).dump(root, writer);
            }
            Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            return true;
        } catch (IOException | RuntimeException e) {
            Log.error("Could not save spawn.yml", e);
            return false;
        }
    }

    private static String string(Object value, String fallback) {
        return value == null ? fallback : String.valueOf(value);
    }

    private static double number(Object value, double fallback) {
        if (value instanceof Number n) return n.doubleValue();
        if (value instanceof String s) {
            try { return Double.parseDouble(s.trim()); } catch (NumberFormatException ignored) { }
        }
        return fallback;
    }
}
