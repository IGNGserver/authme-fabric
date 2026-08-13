package io.github.authme.fabric.converter;

import io.github.authme.fabric.datasource.DataSource;

/**
 * Account importer / database migration. Mirrors AuthMe's
 * {@code fr.xephi.authme.datasource.converter.Converter} contract: read accounts from one source
 * (another plugin's database, an AuthMe SQLite file, ...) and write them into the configured
 * target {@link DataSource} so they are usable by this port.
 */
public interface Converter {

    /** Result of a conversion run. */
    final class Result {
        private final int imported;
        private final int skipped;
        private final String note;

        public Result(int imported, int skipped, String note) {
            this.imported = imported;
            this.skipped = skipped;
            this.note = note;
        }

        public int getImported() { return imported; }
        public int getSkipped() { return skipped; }
        public String getNote() { return note == null ? "" : note; }
    }

    /**
     * @return a short, lowercase identifier used in config and on the command line, e.g.
     *         {@code "sqlitetosql"}.
     */
    String id();

    /** @return a human-readable description shown in {@code /authme converter list}. */
    String description();

    /**
     * Run the conversion, importing accounts into the given target.
     *
     * @param target the active AuthMe-style data source (MySQL, MariaDB, PostgreSQL, ...)
     * @return a populated {@link Result}
     */
    Result convert(DataSource target) throws Exception;
}