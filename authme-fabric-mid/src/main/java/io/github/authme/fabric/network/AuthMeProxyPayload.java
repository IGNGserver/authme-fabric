package io.github.authme.fabric.network;

import io.netty.buffer.ByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;

/** Raw authme:main plugin-message payload for the 1.20.5–1.21.10 line. */
public record AuthMeProxyPayload(byte[] data) implements CustomPacketPayload {

    private static final int MAX_PAYLOAD_BYTES = 32_767;

    public static final Type<AuthMeProxyPayload> TYPE =
        new Type<>(ResourceLocation.fromNamespaceAndPath("authme", "main"));
    public static final StreamCodec<ByteBuf, AuthMeProxyPayload> CODEC = StreamCodec.of(
        (buf, payload) -> {
            byte[] data = payload.data();
            if (data.length > MAX_PAYLOAD_BYTES) throw new IllegalArgumentException("AuthMe proxy payload is too large");
            buf.writeBytes(data);
        },
        buf -> {
            if (buf.readableBytes() > MAX_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("AuthMe proxy payload is too large");
            }
            byte[] data = new byte[buf.readableBytes()];
            buf.readBytes(data);
            return new AuthMeProxyPayload(data);
        });

    public AuthMeProxyPayload {
        data = data == null ? new byte[0] : data.clone();
        if (data.length > MAX_PAYLOAD_BYTES) throw new IllegalArgumentException("AuthMe proxy payload is too large");
    }
    @Override public byte[] data() { return data.clone(); }
    @Override public Type<? extends CustomPacketPayload> type() { return TYPE; }
}
