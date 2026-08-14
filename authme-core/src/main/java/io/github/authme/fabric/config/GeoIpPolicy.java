package io.github.authme.fabric.config;

import io.github.authme.fabric.util.Log;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Country admission policy compatible with AuthMe's Protection.countries and
 * Protection.countriesBlacklist keys.
 *
 * <p>Fabric does not have Bukkit's downloader/plugin lifecycle, so the policy
 * uses an explicit operator-owned database file.  This avoids an
 * unauthenticated server making arbitrary outbound requests.  The default is
 * {@code config/authme/geoip-countries.csv}; a configured {@code .mmdb} file
 * is read directly in the MaxMind DB format, while CSV lines use
 * {@code CIDR,CODE}.  Localhost is always recognized as LOCALHOST.</p>
 */
public final class GeoIpPolicy {

    private final boolean enabled;
    private final boolean failClosed;
    private final Set<String> whitelist;
    private final Set<String> blacklist;
    private final List<Range> ranges;
    private final MaxMindCountryDatabase maxMind;
    private boolean mappingAvailable;

    public GeoIpPolicy(AuthMeConfig config) {
        this.enabled = config.geoIpEnabled();
        this.failClosed = config.geoIpFailClosed();
        this.whitelist = upper(config.geoIpWhitelist());
        this.blacklist = upper(config.geoIpBlacklist());
        this.ranges = new ArrayList<>();
        MaxMindCountryDatabase database = null;
        if (enabled && (!whitelist.isEmpty() || !blacklist.isEmpty())) {
            Path file = config.geoIpFile();
            if (file != null && file.getFileName() != null
                && file.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".mmdb")) {
                try {
                    database = MaxMindCountryDatabase.open(file);
                    mappingAvailable = true;
                    Log.info("Loaded MaxMind GeoIP database from " + file);
                } catch (IOException | RuntimeException e) {
                    Log.warn("Could not load MaxMind GeoIP database " + file + ": " + e.getMessage());
                }
            } else {
                load(file);
            }
        }
        this.maxMind = database;
    }

    public boolean enabled() { return enabled; }
    public boolean mappingAvailable() { return mappingAvailable; }

    /** Returns the ISO country code or LOCALHOST/-- for an unresolved address. */
    public String countryCode(String address) {
        InetAddress ip = parse(address);
        if (ip == null) return "--";
        if (ip.isLoopbackAddress() || ip.isAnyLocalAddress() || ip.isLinkLocalAddress()) return "LOCALHOST";
        if (maxMind != null) {
            String code = maxMind.countryCode(ip);
            return code == null ? "--" : code;
        }
        byte[] bytes = ip.getAddress();
        for (Range range : ranges) if (range.matches(bytes)) return range.code;
        return "--";
    }

    /** Applies AuthMe's whitelist-first/blacklist-second semantics. */
    public boolean isAllowed(String address) {
        if (!enabled || (whitelist.isEmpty() && blacklist.isEmpty())) return true;
        if (!mappingAvailable && !isLocal(address)) return !failClosed;
        String code = countryCode(address);
        if (blacklist.contains(code)) return false;
        return whitelist.isEmpty() || whitelist.contains(code);
    }

    private void load(Path configured) {
        Path file = configured;
        if (file == null || !Files.isRegularFile(file)) {
            Log.warn("GeoIP country restrictions are configured, but no mapping file was found at "
                + (file == null ? "<unset>" : file));
            return;
        }
        try {
            long size = Files.size(file);
            if (size > 8L * 1024L * 1024L) {
                Log.warn("GeoIP mapping file is larger than 8 MiB; refusing to load it");
                return;
            }
            for (String line : Files.readAllLines(file)) {
                String value = line.trim();
                if (value.isEmpty() || value.startsWith("#")) continue;
                String[] parts = value.split("[,=]", 2);
                if (parts.length != 2) continue;
                Range range = Range.parse(parts[0].trim(), parts[1].trim());
                if (range != null) ranges.add(range);
            }
            mappingAvailable = !ranges.isEmpty();
            if (mappingAvailable) Log.info("Loaded " + ranges.size() + " GeoIP country ranges from " + file);
            else Log.warn("GeoIP mapping file contained no valid CIDR entries: " + file);
        } catch (IOException | RuntimeException e) {
            Log.warn("Could not load GeoIP country mapping file " + file + ": " + e.getMessage());
        }
    }

    private static Set<String> upper(List<String> values) {
        Set<String> out = new HashSet<>();
        for (String value : values) if (value != null && !value.isBlank()) out.add(value.trim().toUpperCase(Locale.ROOT));
        return Set.copyOf(out);
    }

    private static boolean isLocal(String address) {
        InetAddress ip = parse(address);
        return ip != null && (ip.isLoopbackAddress() || ip.isAnyLocalAddress() || ip.isLinkLocalAddress());
    }

    private static InetAddress parse(String address) {
        if (address == null || address.isBlank()) return null;
        String value = address.trim();
        if (value.startsWith("/")) value = value.substring(1);
        if (value.startsWith("[") && value.contains("]")) value = value.substring(1, value.indexOf(']'));
        else if (value.indexOf(':') > 0 && value.indexOf(':') == value.lastIndexOf(':')) value = value.substring(0, value.lastIndexOf(':'));
        try { return InetAddress.getByName(value); } catch (IOException | RuntimeException ignored) { return null; }
    }

    private record Range(byte[] network, int prefix, String code) {
        static Range parse(String cidr, String code) {
            if (cidr.isBlank() || code.isBlank()) return null;
            String host = cidr;
            int slash = cidr.indexOf('/');
            int prefix;
            if (slash >= 0) {
                host = cidr.substring(0, slash);
                try { prefix = Integer.parseInt(cidr.substring(slash + 1)); } catch (NumberFormatException e) { return null; }
            } else prefix = -1;
            try {
                InetAddress ip = InetAddress.getByName(host);
                if (prefix < 0) prefix = ip.getAddress().length * 8;
                if (prefix < 0 || prefix > ip.getAddress().length * 8) return null;
                return new Range(mask(ip.getAddress(), prefix), prefix, code.toUpperCase(Locale.ROOT));
            } catch (IOException | RuntimeException e) { return null; }
        }

        boolean matches(byte[] candidate) {
            if (candidate.length != network.length) return false;
            int full = prefix / 8;
            int remainder = prefix % 8;
            for (int i = 0; i < full; i++) if (candidate[i] != network[i]) return false;
            return remainder == 0 || (candidate[full] & (0xff << (8 - remainder)))
                == (network[full] & (0xff << (8 - remainder)));
        }

        private static byte[] mask(byte[] address, int prefix) {
            byte[] result = address.clone();
            int full = prefix / 8;
            int remainder = prefix % 8;
            if (full < result.length) {
                if (remainder != 0) result[full] = (byte) (result[full] & (0xff << (8 - remainder)));
                int start = remainder == 0 ? full : full + 1;
                for (int i = start; i < result.length; i++) result[i] = 0;
            }
            return result;
        }
    }
}
