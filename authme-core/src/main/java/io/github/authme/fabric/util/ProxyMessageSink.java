package io.github.authme.fabric.util;

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * Platform bridge used by the core authentication code to emit an AuthMe proxy
 * message without depending on a particular Minecraft/Fabric networking API.
 */
@FunctionalInterface
public interface ProxyMessageSink {

    /** Sends a protocol message for the named player through the configured proxy bridge. */
    void send(String type, String playerName);

    /** Sends a full premium state snapshot using the AuthMe chunk format. */
    default void sendPremiumList(List<String> playerNames) {
        List<String> names = playerNames == null ? List.of() : playerNames.stream()
            .filter(name -> name != null && !name.isBlank())
            .map(name -> name.toLowerCase(Locale.ROOT))
            .filter(name -> name.matches("[A-Za-z0-9_-]{1,16}"))
            .distinct()
            .collect(Collectors.toList());
        if (names.isEmpty()) {
            send(ProxyProtocol.PREMIUM_LIST_CHUNK, "0:1:");
            return;
        }
        final int chunkSize = 1000;
        int chunks = (names.size() + chunkSize - 1) / chunkSize;
        for (int i = 0; i < chunks; i++) {
            int from = i * chunkSize;
            int to = Math.min(names.size(), from + chunkSize);
            String csv = String.join(",", names.subList(from, to));
            send(ProxyProtocol.PREMIUM_LIST_CHUNK,
                i + ":" + (i == chunks - 1 ? "1" : "0") + ":" + csv);
        }
    }
}
