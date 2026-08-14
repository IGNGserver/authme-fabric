package io.github.authme.fabric.util;

import io.github.authme.fabric.security.HashUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AuthMeBungee/AuthMeVelocity's {@code authme:main} wire format.
 *
 * <p>The original protocol is a sequence of Java modified-UTF strings.  The
 * only message which can cause an automatic login is {@code perform.login};
 * that message is accepted only after a timestamped HMAC check.  This class is
 * deliberately platform independent so all supported Fabric lines share the
 * same parser and security rules.</p>
 */
public final class ProxyProtocol {

    public static final String PROXY_STARTED = "proxy.started";
    public static final String LOGIN = "login";
    public static final String LOGOUT = "logout";
    public static final String PERFORM_LOGIN = "perform.login";
    public static final String PERFORM_LOGIN_ACK = "perform.login.ack";
    public static final String PREMIUM_SET = "premium.set";
    public static final String PREMIUM_PENDING_SET = "premium.pending.set";
    public static final String PREMIUM_UNSET = "premium.unset";
    public static final String PREMIUM_LIST = "premium.list";
    public static final String PREMIUM_LIST_CHUNK = "premium.list.chunk";

    private static final long MAX_AGE_MILLIS = 30_000L;
    private static final int MAX_PAYLOAD_BYTES = 32_767;
    private static final int MAX_STRING_BYTES = 32_767;
    private static final ConcurrentHashMap<String, Long> RECENT_PERFORM_LOGINS = new ConcurrentHashMap<>();

    private ProxyProtocol() {
    }

    /** Encodes the two-string messages used for login/logout notifications and ACKs. */
    public static byte[] encode(String type, String playerName) {
        if (!isKnownType(type) || !validArgument(type, playerName)) {
            throw new IllegalArgumentException("Invalid AuthMe proxy message");
        }
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(128);
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeUTF(type);
            out.writeUTF(isPlayerArgument(type) ? playerName.toLowerCase(java.util.Locale.ROOT) : playerName);
            out.flush();
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Could not encode AuthMe proxy message", e);
        }
    }

    /**
     * Parses a proxy message.  Non-login messages are returned without a
     * secret; {@code perform.login} is returned only when its HMAC is valid.
     */
    public static Incoming parse(byte[] payload, String sharedSecret) {
        if (payload == null || payload.length == 0 || payload.length > MAX_PAYLOAD_BYTES) return null;
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload));
            String type = readUtf(in, 128);
            String playerName = readUtf(in, MAX_STRING_BYTES);
            if (!isKnownType(type) || !validArgument(type, playerName)) return null;
            if (isPlayerArgument(type)) playerName = playerName.toLowerCase(java.util.Locale.ROOT);

            if (!PERFORM_LOGIN.equals(type)) {
                return new Incoming(type, playerName, null, false);
            }
            if (sharedSecret == null || sharedSecret.isBlank()) return null;

            long timestamp = in.readLong();
            String uuidOrHmac = readUtf(in, 256);
            UUID premiumUuid = null;
            String hmac = uuidOrHmac;
            if (!uuidOrHmac.isEmpty()) {
                try {
                    premiumUuid = UUID.fromString(uuidOrHmac);
                    hmac = readUtf(in, 256);
                } catch (IllegalArgumentException ignored) {
                    // Backward-compatible form: the UUID field is omitted and
                    // the third string is the HMAC.
                }
            } else {
                hmac = readUtf(in, 256);
            }
            if (!isSafeString(hmac) || Math.abs(System.currentTimeMillis() - timestamp) > MAX_AGE_MILLIS) {
                return null;
            }
            String signed = playerName + ":" + timestamp + ":" + (premiumUuid == null ? "" : premiumUuid);
            String expected = HashUtils.hmacSha256(sharedSecret, signed);
            if (!HashUtils.isEqual(expected, hmac)) return null;

            // Timestamped HMACs are already short-lived.  Remember the exact
            // signed message as well so a captured packet cannot be replayed
            // repeatedly during that 30-second window.
            String replayKey = playerName + ":" + timestamp + ":" + hmac;
            long now = System.currentTimeMillis();
            RECENT_PERFORM_LOGINS.entrySet().removeIf(e -> now - e.getValue() > MAX_AGE_MILLIS);
            if (RECENT_PERFORM_LOGINS.putIfAbsent(replayKey, now) != null) return null;
            return new Incoming(type, playerName, premiumUuid, true);
        } catch (IllegalArgumentException | IOException e) {
            return null;
        }
    }

    /** Builds the signed perform.login packet used by proxy integration tests and operators. */
    public static byte[] encodePerformLogin(String secret, String playerName, long timestamp, UUID premiumUuid) {
        if (secret == null || secret.isBlank() || !isSafePlayerName(playerName)) {
            throw new IllegalArgumentException("Proxy secret and player name are required");
        }
        String normalized = playerName.toLowerCase(java.util.Locale.ROOT);
        String signed = normalized + ":" + timestamp + ":" + (premiumUuid == null ? "" : premiumUuid);
        String hmac = HashUtils.hmacSha256(secret, signed);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(160);
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeUTF(PERFORM_LOGIN);
            out.writeUTF(normalized);
            out.writeLong(timestamp);
            out.writeUTF(premiumUuid == null ? "" : premiumUuid.toString());
            out.writeUTF(hmac);
            out.flush();
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Could not encode AuthMe perform.login message", e);
        }
    }

    /** Encodes the standard BungeeCord/Velocity Connect plugin-message payload. */
    public static byte[] encodeConnect(String serverName) {
        if (serverName == null || !serverName.matches("[A-Za-z0-9_.-]{1,64}")) {
            throw new IllegalArgumentException("Invalid proxy destination server");
        }
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(96);
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeUTF("Connect");
            out.writeUTF(serverName);
            out.flush();
            return bytes.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Could not encode proxy connect message", e);
        }
    }

    public static boolean isProxyIdentity(String value) {
        return "bungee".equalsIgnoreCase(value) || "velocity".equalsIgnoreCase(value);
    }

    private static String readUtf(DataInputStream in, int maxBytes) throws IOException {
        int before = in.available();
        String value = in.readUTF();
        int consumed = before - in.available();
        if (consumed > maxBytes + 2) throw new IOException("AuthMe proxy string is too large");
        return value;
    }

    private static boolean validArgument(String type, String argument) {
        if (!isSafeString(argument)) return false;
        if (isPlayerArgument(type)) return isSafePlayerName(argument);
        if (PROXY_STARTED.equals(type)) return argument.length() <= 64;
        if (PREMIUM_LIST.equals(type)) return validPremiumCsv(argument);
        if (PREMIUM_LIST_CHUNK.equals(type)) return validPremiumChunk(argument);
        return false;
    }

    private static boolean isPlayerArgument(String type) {
        return LOGIN.equals(type) || LOGOUT.equals(type) || PERFORM_LOGIN.equals(type)
            || PERFORM_LOGIN_ACK.equals(type) || PREMIUM_SET.equals(type)
            || PREMIUM_PENDING_SET.equals(type) || PREMIUM_UNSET.equals(type);
    }

    private static boolean isKnownType(String type) {
        return PROXY_STARTED.equals(type) || isPlayerArgument(type)
            || PREMIUM_LIST.equals(type) || PREMIUM_LIST_CHUNK.equals(type);
    }

    private static boolean validPremiumCsv(String csv) {
        if (csv == null || csv.isEmpty()) return true;
        for (String name : csv.split(",", -1)) if (!isSafePlayerName(name)) return false;
        return true;
    }

    private static boolean validPremiumChunk(String value) {
        String[] parts = value.split(":", 3);
        if (parts.length != 3 || !("0".equals(parts[1]) || "1".equals(parts[1]))) return false;
        try {
            int sequence = Integer.parseInt(parts[0]);
            if (sequence < 0 || sequence > 1_000_000) return false;
        } catch (NumberFormatException e) {
            return false;
        }
        return validPremiumCsv(parts[2]);
    }

    private static boolean isSafePlayerName(String value) {
        return value != null && value.length() >= 1 && value.length() <= 16
            && value.chars().allMatch(c -> c == '_' || c == '-' || c >= '0' && c <= '9'
                || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z');
    }

    private static boolean isSafeString(String value) {
        return value != null && !value.isEmpty() && value.length() <= MAX_STRING_BYTES
            && value.getBytes(StandardCharsets.UTF_8).length <= MAX_STRING_BYTES;
    }

    public record Incoming(String type, String playerName, UUID premiumUuid, boolean verified) {
    }
}
