package io.github.authme.fabric.network;

import io.netty.buffer.ByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;

/** Raw authme:main plugin-message payload for Minecraft 1.21.11. */
public record AuthMeProxyPayload(byte[] data) implements CustomPacketPayload {

    public static final Type<AuthMeProxyPayload> TYPE =
        new Type<>(Identifier.fromNamespaceAndPath("authme", "main"));
    public static final StreamCodec<ByteBuf, AuthMeProxyPayload> CODEC = StreamCodec.of(
        (buf, payload) -> buf.writeBytes(payload.data()),
        buf -> {
            byte[] data = new byte[buf.readableBytes()];
            buf.readBytes(data);
            return new AuthMeProxyPayload(data);
        });

    public AuthMeProxyPayload {
        data = data == null ? new byte[0] : data.clone();
    }

    @Override
    public byte[] data() { return data.clone(); }

    @Override
    public Type<? extends CustomPacketPayload> type() { return TYPE; }
}
