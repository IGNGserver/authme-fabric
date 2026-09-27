package io.github.authme.fabric.datasource;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayDeque;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * A small, dependency-free bounded connection pool (replaces HikariCP to avoid bundling slf4j).
 * Connections are validated before reuse and idle/stale connections are closed.
 */
public final class SimpleConnectionPool {

    private final String jdbcUrl;
    private final Properties props;
    private final int maxSize;
    private final long maxLifetimeMillis;
    private final ArrayDeque<IdleConnection> idle = new ArrayDeque<>();
    private final Map<Connection, Long> createdAt = new IdentityHashMap<>();
    private int inUse = 0;
    private boolean closed = false;

    public SimpleConnectionPool(String jdbcUrl, String user, String password, int maxSize) {
        this(jdbcUrl, user, password, maxSize, 0);
    }

    public SimpleConnectionPool(String jdbcUrl, String user, String password, int maxSize, int maxLifetimeSeconds) {
        this.jdbcUrl = jdbcUrl;
        this.maxSize = Math.max(2, maxSize);
        this.maxLifetimeMillis = lifetimeMillis(maxLifetimeSeconds);
        this.props = new Properties();
        if (user != null) this.props.setProperty("user", user);
        if (password != null) this.props.setProperty("password", password);
    }

    public SimpleConnectionPool(String jdbcUrl, Properties props, int maxSize) {
        this(jdbcUrl, props, maxSize, 0);
    }

    public SimpleConnectionPool(String jdbcUrl, Properties props, int maxSize, int maxLifetimeSeconds) {
        this.jdbcUrl = jdbcUrl;
        this.props = props;
        this.maxSize = Math.max(2, maxSize);
        this.maxLifetimeMillis = lifetimeMillis(maxLifetimeSeconds);
    }

    /**
     * Borrows a valid connection, blocking up to {@code timeoutMillis} if the pool is exhausted.
     *
     * @throws SQLException if no connection can be obtained within the timeout
     */
    public Connection borrow(long timeoutMillis) throws SQLException {
        long deadline = System.currentTimeMillis() + Math.max(0, timeoutMillis);
        while (true) {
            synchronized (this) {
                if (closed) throw new SQLException("Connection pool is closed");
                while (!idle.isEmpty()) {
                    IdleConnection entry = idle.poll();
                    if (entry == null) break;
                    Connection c = entry.connection;
                    try {
                        boolean youngEnough = maxLifetimeMillis <= 0
                            || System.currentTimeMillis() - entry.createdAt < maxLifetimeMillis;
                        if (youngEnough && !c.isClosed() && c.isValid(2)) {
                            inUse++;
                            return c;
                        }
                        discard(c);
                    } catch (SQLException e) {
                        discard(c);
                    }
                }
                if (inUse < maxSize) {
                    // Reserve a slot, but establish the JDBC connection after leaving the monitor.
                    // A slow or unavailable database must not prevent another thread from
                    // returning a healthy borrowed connection to the pool.
                    inUse++;
                } else {
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
                    continue;
                }
            }

            Connection connection;
            try {
                connection = DriverManager.getConnection(jdbcUrl, props);
            } catch (SQLException e) {
                releaseReservation();
                throw e;
            }
            synchronized (this) {
                if (closed) {
                    if (inUse > 0) inUse--;
                    notifyAll();
                    closeQuietly(connection);
                    throw new SQLException("Connection pool is closed");
                }
                createdAt.put(connection, System.currentTimeMillis());
                return connection;
            }
        }
    }

    private synchronized void releaseReservation() {
        if (inUse > 0) inUse--;
        notifyAll();
    }

    public synchronized void release(Connection c) {
        if (c == null) return;
        if (inUse > 0) inUse--;
        if (closed) {
            discard(c);
            notifyAll();
            return;
        }
        try {
            if (!c.isClosed() && !c.getAutoCommit()) {
                try { c.rollback(); } catch (SQLException ignored) { }
                c.setAutoCommit(true);
            }
        } catch (SQLException e) {
            discard(c);
            notifyAll();
            return;
        }
        try {
            if (c.isClosed()) {
                discard(c);
            } else if (expired(c) || !c.isValid(1)) {
                discard(c);
            } else {
                idle.offer(new IdleConnection(c, createdAt.getOrDefault(c, System.currentTimeMillis())));
            }
        } catch (SQLException e) {
            discard(c);
        }
        notifyAll();
    }

    public synchronized void close() {
        closed = true;
        for (IdleConnection entry : idle) discard(entry.connection);
        idle.clear();
        notifyAll();
    }

    private boolean expired(Connection c) {
        Long created = createdAt.get(c);
        return maxLifetimeMillis > 0 && created != null
            && System.currentTimeMillis() - created >= maxLifetimeMillis;
    }

    private void discard(Connection c) {
        createdAt.remove(c);
        closeQuietly(c);
    }

    private static void closeQuietly(Connection c) {
        if (c == null) return;
        try { c.close(); } catch (SQLException ignored) { }
    }

    private static long lifetimeMillis(int seconds) {
        return seconds <= 0 ? 0L : Math.max(1L, seconds) * 1000L;
    }

    private static final class IdleConnection {
        final Connection connection;
        final long createdAt;

        IdleConnection(Connection connection, long createdAt) {
            this.connection = connection;
            this.createdAt = createdAt;
        }
    }
}
