package io.github.authme.fabric.config;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Small, read-only MaxMind DB reader used only for country-code lookups.
 *
 * <p>The project intentionally does not add a GeoIP dependency to the Fabric
 * jar.  This reader implements the stable MaxMind DB binary format directly,
 * including 24/28/32-bit search-tree records and the data types needed by
 * GeoLite2-Country/GeoIP2-Country files.</p>
 */
public final class MaxMindCountryDatabase {
    private static final byte[] MARKER = new byte[] {
        (byte) 0xab, (byte) 0xcd, (byte) 0xef, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'
    };
    private static final int MAX_FILE_BYTES = 256 * 1024 * 1024;
    private static final int MAX_FIELD_BYTES = 16 * 1024 * 1024;
    private static final int MAX_CONTAINER_ITEMS = 100_000;

    private final byte[] data;
    private final int nodeCount;
    private final int recordSize;
    private final int ipVersion;
    private final int treeSize;
    private final int dataSectionOffset;
    private final int metadataOffset;

    private MaxMindCountryDatabase(byte[] data, int nodeCount, int recordSize, int ipVersion,
                                   int treeSize, int dataSectionOffset, int metadataOffset) {
        this.data = data;
        this.nodeCount = nodeCount;
        this.recordSize = recordSize;
        this.ipVersion = ipVersion;
        this.treeSize = treeSize;
        this.dataSectionOffset = dataSectionOffset;
        this.metadataOffset = metadataOffset;
    }

    public static MaxMindCountryDatabase open(Path file) throws IOException {
        long size = Files.size(file);
        if (size <= 0 || size > MAX_FILE_BYTES) {
            throw new IOException("MaxMind database size is outside the safe limit");
        }
        byte[] data = Files.readAllBytes(file);
        int marker = findLastMarker(data);
        if (marker < 0 || data.length - marker > 128 * 1024) {
            throw new IOException("MaxMind metadata marker was not found");
        }
        int metadataOffset = marker + MARKER.length;
        Object metadata = new ValueReader(data, metadataOffset, data.length, metadataOffset).readRoot();
        if (!(metadata instanceof Map<?, ?> map)) {
            throw new IOException("MaxMind metadata is not a map");
        }
        int nodeCount = number(map.get("node_count"), "node_count");
        int recordSize = number(map.get("record_size"), "record_size");
        int ipVersion = number(map.get("ip_version"), "ip_version");
        if (nodeCount <= 0 || recordSize < 24 || recordSize % 4 != 0 || ipVersion != 4 && ipVersion != 6) {
            throw new IOException("Unsupported MaxMind metadata values");
        }
        long treeSizeLong = ((long) recordSize * 2L / 8L) * nodeCount;
        long dataSectionLong = treeSizeLong + 16L;
        if (treeSizeLong > Integer.MAX_VALUE || dataSectionLong > marker
            || dataSectionLong < 0 || metadataOffset <= dataSectionLong) {
            throw new IOException("Invalid MaxMind search tree size");
        }
        return new MaxMindCountryDatabase(data, nodeCount, recordSize, ipVersion,
            (int) treeSizeLong, (int) dataSectionLong, metadataOffset);
    }

    /** Returns the ISO-3166 alpha-2 code for an address, or {@code null}. */
    public String countryCode(InetAddress address) {
        if (address == null) return null;
        byte[] addressBytes = address.getAddress();
        if (ipVersion == 6 && addressBytes.length == 4) {
            byte[] mapped = new byte[16];
            mapped[10] = (byte) 0xff;
            mapped[11] = (byte) 0xff;
            System.arraycopy(addressBytes, 0, mapped, 12, 4);
            addressBytes = mapped;
        } else if (ipVersion == 4 && addressBytes.length == 16) {
            if (!isIpv4Mapped(addressBytes)) return null;
            byte[] v4 = new byte[4];
            System.arraycopy(addressBytes, 12, v4, 0, 4);
            addressBytes = v4;
        }
        int bitCount = ipVersion == 4 ? 32 : 128;
        if (addressBytes.length * 8 != bitCount) return null;

        long node = 0;
        for (int bitIndex = 0; bitIndex < bitCount; bitIndex++) {
            if (node == nodeCount) return null;
            if (node > nodeCount) return countryAtPointer(node);
            int bit = (addressBytes[bitIndex / 8] >>> (7 - (bitIndex % 8))) & 1;
            node = readNode(node, bit);
        }
        return node > nodeCount ? countryAtPointer(node) : null;
    }

    private String countryAtPointer(long pointer) {
        long offset = (long) treeSize + pointer - nodeCount;
        if (offset < dataSectionOffset || offset >= metadataOffset || offset > Integer.MAX_VALUE) return null;
        try {
            Object value = new ValueReader(data, (int) offset, metadataOffset, dataSectionOffset).readRoot();
            return extractCountryCode(value);
        } catch (IOException | RuntimeException ignored) {
            return null;
        }
    }

    private long readNode(long node, int branch) {
        if (node < 0 || node >= nodeCount) return nodeCount;
        long offset = node * ((long) recordSize * 2L / 8L);
        long nodeBytes = (long) recordSize * 2L / 8L;
        if (offset < 0 || offset + nodeBytes > treeSize) return nodeCount;
        return switch (recordSize) {
            case 24 -> readUnsigned(data, (int) offset + branch * 3, 3);
            case 28 -> {
                int base = (int) offset;
                int middle = data[base + 3] & 0xff;
                if (branch == 0) {
                    yield readUnsigned(data, base, 3) | ((long) (middle >>> 4) << 24);
                }
                yield readUnsigned(data, base + 4, 3) | ((long) (middle & 0x0f) << 24);
            }
            case 32 -> readUnsigned(data, (int) offset + branch * 4, 4);
            default -> nodeCount;
        };
    }

    private static String extractCountryCode(Object value) {
        if (value instanceof String text && text.matches("[A-Za-z]{2}")) return text.toUpperCase(java.util.Locale.ROOT);
        if (!(value instanceof Map<?, ?> map)) return null;
        Object country = map.get("country");
        String direct = codeFromMap(country);
        if (direct != null) return direct;
        direct = codeFromMap(map);
        if (direct != null) return direct;
        for (String key : List.of("registered_country", "represented_country")) {
            direct = codeFromMap(map.get(key));
            if (direct != null) return direct;
        }
        return null;
    }

    private static String codeFromMap(Object value) {
        if (!(value instanceof Map<?, ?> map)) return null;
        Object code = map.get("iso_code");
        return code instanceof String text && text.matches("[A-Za-z]{2}")
            ? text.toUpperCase(java.util.Locale.ROOT) : null;
    }

    private static int findLastMarker(byte[] data) {
        outer:
        for (int i = data.length - MARKER.length; i >= 0; i--) {
            for (int j = 0; j < MARKER.length; j++) if (data[i + j] != MARKER[j]) continue outer;
            return i;
        }
        return -1;
    }

    private static int number(Object value, String name) throws IOException {
        if (value instanceof Number n) {
            long result = n.longValue();
            if (result >= 0 && result <= Integer.MAX_VALUE) return (int) result;
        }
        if (value instanceof BigInteger n && n.signum() >= 0 && n.bitLength() <= 31) return n.intValue();
        throw new IOException("Invalid MaxMind metadata field: " + name);
    }

    private static long readUnsigned(byte[] data, int offset, int length) {
        long value = 0;
        for (int i = 0; i < length; i++) value = (value << 8) | (data[offset + i] & 0xffL);
        return value;
    }

    private static boolean isIpv4Mapped(byte[] value) {
        for (int i = 0; i < 10; i++) if (value[i] != 0) return false;
        return value[10] == (byte) 0xff && value[11] == (byte) 0xff;
    }

    private static final class ValueReader {
        private final byte[] data;
        private final int limit;
        private final int pointerBase;

        private ValueReader(byte[] data, int offset, int limit, int pointerBase) {
            this.data = data;
            this.limit = limit;
            this.pointerBase = pointerBase;
            this.rootOffset = offset;
        }

        private final int rootOffset;

        Object readRoot() throws IOException {
            return read(new Cursor(rootOffset), 0);
        }

        private Object read(Cursor cursor, int depth) throws IOException {
            if (depth > 32) throw new IOException("MaxMind pointer nesting is too deep");
            int control = cursor.readUnsignedByte();
            int type = control >>> 5;
            int size = control & 0x1f;
            if (type == 0) type = cursor.readUnsignedByte() + 7;
            if (type == 1) {
                long pointer = readPointer(cursor, size);
                long target = (long) pointerBase + pointer;
                if (target < 0 || target >= limit || target > Integer.MAX_VALUE) throw new IOException("Invalid MaxMind pointer");
                return read(new Cursor((int) target), depth + 1);
            }
            int length = readSize(cursor, size);
            return switch (type) {
                case 2 -> newString(cursor.readBytes(length));
                case 3 -> {
                    if (length != 8) throw new IOException("Invalid MaxMind double length");
                    yield Double.longBitsToDouble(cursor.readUnsignedInt(8));
                }
                case 4 -> cursor.readBytes(length);
                case 5, 6, 9, 10 -> readInteger(cursor, length, type);
                case 7 -> readMap(cursor, length, depth);
                case 8 -> {
                    if (length > 4) throw new IOException("Invalid MaxMind signed integer length");
                    yield (int) readSigned(cursor, length);
                }
                case 11 -> readArray(cursor, length, depth);
                case 14 -> {
                    if (length > 1) throw new IOException("Invalid MaxMind boolean");
                    yield length == 1;
                }
                case 15 -> {
                    if (length != 4) throw new IOException("Invalid MaxMind float length");
                    yield Float.intBitsToFloat((int) cursor.readUnsignedInt(4));
                }
                default -> throw new IOException("Unsupported MaxMind data type: " + type);
            };
        }

        private Map<String, Object> readMap(Cursor cursor, int count, int depth) throws IOException {
            if (count > MAX_CONTAINER_ITEMS) throw new IOException("MaxMind map is too large");
            Map<String, Object> result = new LinkedHashMap<>();
            for (int i = 0; i < count; i++) {
                Object key = read(cursor, depth + 1);
                if (!(key instanceof String text)) throw new IOException("MaxMind map key is not a string");
                result.put(text, read(cursor, depth + 1));
            }
            return result;
        }

        private List<Object> readArray(Cursor cursor, int count, int depth) throws IOException {
            if (count > MAX_CONTAINER_ITEMS) throw new IOException("MaxMind array is too large");
            List<Object> result = new ArrayList<>(count);
            for (int i = 0; i < count; i++) result.add(read(cursor, depth + 1));
            return result;
        }

        private Object readInteger(Cursor cursor, int length, int type) throws IOException {
            if (length > 16) throw new IOException("Invalid MaxMind integer length");
            if (length == 0) return 0L;
            if (type == 10 || length > 8) {
                return new BigInteger(1, cursor.readBytes(length));
            }
            return cursor.readUnsignedInt(length);
        }

        private long readSigned(Cursor cursor, int length) throws IOException {
            long value = cursor.readUnsignedInt(length);
            if (length == 4 && (value & 0x80000000L) != 0) return value - 0x1_0000_0000L;
            return value;
        }

        private long readPointer(Cursor cursor, int sizeBits) throws IOException {
            int pointerSize = (sizeBits >>> 3) & 3;
            int low = sizeBits & 7;
            return switch (pointerSize) {
                case 0 -> ((long) low << 8) | cursor.readUnsignedByte();
                case 1 -> 2048L + (((long) low << 16) | cursor.readUnsignedInt(2));
                case 2 -> 526336L + (((long) low << 24) | cursor.readUnsignedInt(3));
                case 3 -> cursor.readUnsignedInt(4);
                default -> throw new IOException("Invalid MaxMind pointer size");
            };
        }

        private int readSize(Cursor cursor, int sizeBits) throws IOException {
            long size = switch (sizeBits) {
                case 29 -> 29L + cursor.readUnsignedInt(1);
                case 30 -> 285L + cursor.readUnsignedInt(2);
                case 31 -> 65_821L + cursor.readUnsignedInt(3);
                default -> sizeBits;
            };
            if (size < 0 || size > MAX_FIELD_BYTES || size > Integer.MAX_VALUE) {
                throw new IOException("MaxMind field is too large");
            }
            return (int) size;
        }

        private String newString(byte[] value) throws IOException {
            try {
                return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value)).toString();
            } catch (CharacterCodingException e) {
                throw new IOException("Invalid UTF-8 in MaxMind database", e);
            }
        }

        private final class Cursor {
            private int offset;

            private Cursor(int offset) { this.offset = offset; }

            private int readUnsignedByte() throws IOException {
                ensure(1);
                return data[offset++] & 0xff;
            }

            private long readUnsignedInt(int length) throws IOException {
                ensure(length);
                long result = readUnsigned(data, offset, length);
                offset += length;
                return result;
            }

            private byte[] readBytes(int length) throws IOException {
                ensure(length);
                byte[] result = new byte[length];
                System.arraycopy(data, offset, result, 0, length);
                offset += length;
                return result;
            }

            private void ensure(int length) throws IOException {
                if (length < 0 || offset < 0 || offset > limit - length) throw new IOException("Truncated MaxMind database");
            }
        }
    }
}
