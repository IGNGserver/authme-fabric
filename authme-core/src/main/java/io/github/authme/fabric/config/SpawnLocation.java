package io.github.authme.fabric.config;

/** A persisted AuthMe spawn location independent of a particular Minecraft API version. */
public record SpawnLocation(String world, double x, double y, double z, float yaw, float pitch) {

    public SpawnLocation {
        if (world == null || world.isBlank()) world = "minecraft:overworld";
        if (!Double.isFinite(x) || !Double.isFinite(y) || !Double.isFinite(z)
            || !Float.isFinite(yaw) || !Float.isFinite(pitch)) {
            throw new IllegalArgumentException("Spawn coordinates must be finite");
        }
    }
}
