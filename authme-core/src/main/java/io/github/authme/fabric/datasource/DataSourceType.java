package io.github.authme.fabric.datasource;

/**
 * Backend database type. Mirrors AuthMe's {@code DataSourceType}.
 */
public enum DataSourceType {
    SQLITE,
    MARIADB,
    MYSQL,
    POSTGRESQL
}