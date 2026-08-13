package io.github.authme.fabric.converter;

import io.github.authme.fabric.datasource.DataSource;

/**
 * Stub placeholder for converters that aren't yet implemented on this Fabric port. Runs as a no-op
 * so {@code /authme converter list} can advertise them and admins see a clear message when they
 * try to run one that isn't ready.
 */
public final class StubConverter implements Converter {

    private final String id;
    private final String description;

    public StubConverter(String id, String description) {
        this.id = id;
        this.description = description;
    }

    @Override public String id() { return id; }

    @Override public String description() { return description; }

    @Override
    public Result convert(DataSource target) {
        return new Result(0, 0, description);
    }
}