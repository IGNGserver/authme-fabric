package io.github.authme.proxy.core;

import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/** Bounded, thread-safe proxy-side authentication state. */
public final class ProxyAuthenticationStore {

    private static final int MAX_ENTRIES = 16_384;
    private final Map<String, State> states = new ConcurrentHashMap<>();

    public void markAuthenticated(String name) {
        String key = key(name);
        if (key == null) return;
        ensureCapacity(key);
        states.computeIfAbsent(key, ignored -> new State()).authenticated = true;
    }

    public void markLoggedOut(String name) {
        String key = key(name);
        if (key == null) return;
        ensureCapacity(key);
        State state = states.computeIfAbsent(key, ignored -> new State());
        state.authenticated = false;
        // A successful Premium handshake is a connection-scoped identity proof. Do not
        // let /logout replay that proof onto another backend in the same proxy session.
        state.premiumVerified = false;
        state.premiumUuid = null;
    }

    public boolean isAuthenticated(String name) {
        State state = states.get(key(name));
        return state != null && state.authenticated;
    }

    public void clear(String name) {
        String key = key(name);
        if (key != null) states.remove(key);
    }

    public void beginAutoLogin(String name) {
        String key = key(name);
        if (key == null) return;
        ensureCapacity(key);
        states.computeIfAbsent(key, ignored -> new State()).pendingAutoLogin.set(0);
    }

    /** Starts one retry sequence without resetting an already running sequence. */
    public boolean tryBeginAutoLogin(String name) {
        String key = key(name);
        if (key == null) return false;
        ensureCapacity(key);
        return states.computeIfAbsent(key, ignored -> new State())
            .pendingAutoLogin.compareAndSet(-1, 0);
    }

    public boolean isAutoLoginPending(String name) {
        State state = states.get(key(name));
        return state != null && state.pendingAutoLogin.get() >= 0;
    }

    public int nextAutoLoginAttempt(String name) {
        State state = states.get(key(name));
        return state == null ? -1 : state.pendingAutoLogin.getAndIncrement();
    }

    public void cancelAutoLogin(String name) {
        State state = states.get(key(name));
        if (state != null) state.pendingAutoLogin.set(-1);
    }

    public void clearAutoLoginIfIdle(String name) {
        String key = key(name);
        State state = key == null ? null : states.get(key);
        if (state != null && !state.authenticated && !state.premium && !state.premiumVerified
            && state.pendingAutoLogin.get() < 0) states.remove(key, state);
    }

    public void setPremium(String name, boolean premium) {
        String key = key(name);
        if (key == null) return;
        ensureCapacity(key);
        State state = states.computeIfAbsent(key, ignored -> new State());
        state.premium = premium;
        if (!premium) {
            state.premiumVerified = false;
            state.premiumUuid = null;
        }
    }

    public boolean isPremium(String name) {
        State state = states.get(key(name));
        return state != null && state.premium;
    }

    /** Records a proxy-side online-mode identity; it is not an AuthMe session yet. */
    public void markPremiumVerified(String name, UUID uuid) {
        String key = key(name);
        if (key == null || uuid == null) return;
        ensureCapacity(key);
        State state = states.computeIfAbsent(key, ignored -> new State());
        state.premium = true;
        state.premiumVerified = true;
        state.premiumUuid = uuid;
    }

    public boolean isPremiumVerified(String name) {
        State state = states.get(key(name));
        return state != null && state.premiumVerified;
    }

    public void clearPremiumVerification(String name) {
        State state = states.get(key(name));
        if (state != null) {
            state.premiumVerified = false;
            state.premiumUuid = null;
        }
    }

    public void setPremiumUuid(String name, UUID uuid) {
        String key = key(name);
        if (key == null) return;
        ensureCapacity(key);
        states.computeIfAbsent(key, ignored -> new State()).premiumUuid = uuid;
    }

    public UUID premiumUuid(String name) {
        State state = states.get(key(name));
        return state == null ? null : state.premiumUuid;
    }

    private void ensureCapacity(String key) {
        if (states.containsKey(key) || states.size() < MAX_ENTRIES) return;
        Iterator<String> iterator = states.keySet().iterator();
        if (iterator.hasNext()) states.remove(iterator.next());
    }

    private static String key(String name) {
        if (name == null) return null;
        String normalized = name.trim().toLowerCase(Locale.ROOT);
        return normalized.matches("[a-z0-9_-]{1,16}") ? normalized : null;
    }

    private static final class State {
        private volatile boolean authenticated;
        private volatile boolean premium;
        private volatile boolean premiumVerified;
        private volatile UUID premiumUuid;
        private final AtomicInteger pendingAutoLogin = new AtomicInteger(-1);
    }
}
