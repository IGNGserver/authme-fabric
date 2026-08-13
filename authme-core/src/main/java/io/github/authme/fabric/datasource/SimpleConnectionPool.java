package io.github.authme.fabric.datasource;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayDeque;
import java.util.Properties;

/**
 * A small, dependency-free bounded connection pool (replaces HikariCP to avoid bundling slf4j).
 * Connections are validated before reuse and idle/stale connections are closed.
 */
public final class SimpleConnectionPool {

    private final String jdbcUrl;
    private final Properties props;
    private final int maxSize;
    private final ArrayDeque<Connection> idle = new ArrayDeque<>();
    private int inUse = 0;
    private boolean closed = false;

    public SimpleConnectionPool(String jdbcUrl, String user, String password, int maxSize) {
        this.jdbcUrl = jdbcUrl;
        this.maxSize = Math.max(2, maxSize);
        this.props = new Properties();
        if (user != null) this.props.setProperty("user", user);
        if (password != null) this.props.setProperty("password", password);
    }

    public SimpleConnectionPool(String jdbcUrl, Properties props, int maxSize) {
        this.jdbcUrl = jdbcUrl;
        this.props = props;
        this.maxSize = Math.max(2, maxSize);
    }

    /**
     * Borrows a valid connection, blocking up to {@code timeoutMillis} if the pool is exhausted.
     *
     * @throws SQLException if no connection can be obtained within the timeout
     */
    public synchronized Connection borrow(long timeoutMillis) throws SQLException {
        long deadline = System.currentTimeMillis() + Math.max(0, timeoutMillis);
        while (!closed) {
            while (!idle.isEmpty()) {
                Connection c = idle.poll();
                if (c == null) break;
                try {
                    if (!c.isClosed() && c.isValid(2)) {
                        inUse++;
                        return c;
                    }
                    closeQuietly(c);
                } catch (SQLException e) {
                    closeQuietly(c);
                }
            }
            if (inUse < maxSize) {
                inUse++;
                break;
            }
            long wait = deadline - System.currentTimeMillis();
            if (wait <= 0) {
                throw new SQLException("Connection pool exhausted (max=" + maxSize + ")");
            }
            try {
                wait(Math.min(wait, 1000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new SQLException("Interrupted while waiting for a connection", e);
            }
        }
        if (closed) {
            throw new SQLException("Connection pool is closed");
        }
        try {
            return DriverManager.getConnection(jdbcUrl, props);
        } catch (SQLException e) {
            synchronized (this) { if (inUse > 0) inUse--; notifyAll(); }
            throw e;
        }
    }

    public synchronized void release(Connection c) {
        if (c == null) return;
        if (inUse > 0) inUse--;
        if (closed) {
            closeQuietly(c);
            return;
        }
        try {
            if (!c.isClosed() && !c.getAutoCommit()) {
                try { c.rollback(); } catch (SQLException ignored) { }
                c.setAutoCommit(true);
            }
        } catch (SQLException e) {
            closeQuietly(c);
            notifyAll();
            return;
        }
        try {
            if (c.isClosed()) {
                // drop
            } else if (!c.isValid(1)) {
                closeQuietly(c);
            } else {
                idle.offer(c);
            }
        } catch (SQLException e) {
            closeQuietly(c);
        }
        notifyAll();
    }

    public synchronized void close() {
        closed = true;
        for (Connection c : idle) closeQuietly(c);
        idle.clear();
        notifyAll();
    }

    private static void closeQuietly(Connection c) {
        if (c == null) return;
        try { c.close(); } catch (SQLException ignored) { }
    }
}