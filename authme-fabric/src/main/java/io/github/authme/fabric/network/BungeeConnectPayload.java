package io.github.authme.fabric.network;

import io.netty.buffer.ByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.Identifier;

/** Raw BungeeCord Connect plugin-message payload for 1.21.11. */
public record BungeeConnectPayload(byte[] data) implements CustomPacketPayload {
    public static final Type<BungeeConnectPayload> TYPE =
        new Type<>(Identifier.fromNamespaceAndPath("bungeecord", "main"));
    public static final StreamCodec<ByteBuf, BungeeConnectPayload> CODEC = StreamCodec.of(
        (buf, payload) -> buf.writeBytes(payload.data()),
        buf -> {
            byte[] data = new byte[buf.readableBytes()];
            buf.readBytes(data);
            return new BungeeConnectPayload(data);
        });

    public BungeeConnectPayload { data = data == null ? new byte[0] : data.clone(); }
    @Override public byte[] data() { return data.clone(); }
    @Override public Type<? extends CustomPacketPayload> type() { return TYPE; }
}
