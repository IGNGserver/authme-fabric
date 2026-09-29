package io.github.authme.proxy.core;

import io.github.authme.fabric.util.ProxyProtocol;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Strict adapter between platform plugin-message APIs and AuthMe's wire format. */
public final class ProxyMessageCodec {

    public static final String PROXY_STARTED = ProxyProtocol.PROXY_STARTED;
    public static final String LOGIN = ProxyProtocol.LOGIN;
    public static final String LOGOUT = ProxyProtocol.LOGOUT;
    public static final String PERFORM_LOGIN = ProxyProtocol.PERFORM_LOGIN;
    public static final String PERFORM_LOGIN_ACK = ProxyProtocol.PERFORM_LOGIN_ACK;
    public static final String PREMIUM_SET = ProxyProtocol.PREMIUM_SET;
    public static final String PREMIUM_PENDING_SET = ProxyProtocol.PREMIUM_PENDING_SET;
    public static final String PREMIUM_UNSET = ProxyProtocol.PREMIUM_UNSET;
    public static final String PREMIUM_LIST = ProxyProtocol.PREMIUM_LIST;
    public static final String PREMIUM_LIST_CHUNK = ProxyProtocol.PREMIUM_LIST_CHUNK;

    private ProxyMessageCodec() { }

    /**
     * Unsigned backend notifications are no longer trusted. Keep this overload
     * for source compatibility, but make the fail-closed behavior explicit.
     */
    public static Optional<Message> parseBackend(byte[] payload) {
        return Optional.empty();
    }

    /** Parses and authenticates a backend notification with the shared secret. */
    public static Optional<Message> parseBackend(byte[] payload, String sharedSecret) {
        ProxyProtocol.Incoming message = ProxyProtocol.parseBackend(payload, sharedSecret);
        return message == null ? Optional.empty()
            : Optional.of(new Message(message.type(), message.playerName(), message.premiumUuid(),
                message.verified(), message.backendId()));
    }

    public static byte[] performLogin(String playerName, UUID premiumUuid, String secret) {
        return ProxyProtocol.encodePerformLogin(secret, playerName, System.currentTimeMillis(), premiumUuid);
    }

    public static byte[] simple(String type, String playerName) {
        return ProxyProtocol.encode(type, playerName);
    }

    public static byte[] proxyStarted(String identity) {
        return ProxyProtocol.encode(ProxyProtocol.PROXY_STARTED, identity);
    }

    public static byte[] proxyStarted(String identity, String secret) {
        return ProxyProtocol.encodeSignedProxyStarted(secret, identity, System.currentTimeMillis());
    }

    public static byte[] premiumList(String csv) {
        return ProxyProtocol.encode(ProxyProtocol.PREMIUM_LIST, csv == null ? "" : csv);
    }

    /** Encodes an authenticated backend-to-proxy notification. */
    public static byte[] signedBackend(String type, String playerName, String sharedSecret,
                                       String backendId) {
        return ProxyProtocol.encodeSignedBackend(sharedSecret, backendId, type, playerName);
    }

    /**
     * Parses one bounded premium snapshot chunk after the wire-level parser has
     * authenticated and size-checked the message.
     */
    public static Optional<PremiumChunk> parsePremiumChunk(String value) {
        if (value == null) return Optional.empty();
        String[] parts = value.split(":", 3);
        if (parts.length != 3 || !("0".equals(parts[1]) || "1".equals(parts[1]))) {
            return Optional.empty();
        }
        final int sequence;
        try {
            sequence = Integer.parseInt(parts[0]);
        } catch (NumberFormatException exception) {
            return Optional.empty();
        }
        if (sequence < 0 || sequence > 1_000_000) return Optional.empty();
        List<String> names = new ArrayList<>();
        if (!parts[2].isEmpty()) {
            String[] rawNames = parts[2].split(",", -1);
            if (rawNames.length > 1_000) return Optional.empty();
            for (String rawName : rawNames) {
                if (!rawName.matches("[A-Za-z0-9_-]{1,16}")) return Optional.empty();
                names.add(rawName.toLowerCase(java.util.Locale.ROOT));
            }
        }
        return Optional.of(new PremiumChunk(sequence, "1".equals(parts[1]), List.copyOf(names)));
    }

    public record Message(String type, String playerName, UUID premiumUuid, boolean verified,
                          String backendId) { }

    public record PremiumChunk(int sequence, boolean last, List<String> names) { }
}
