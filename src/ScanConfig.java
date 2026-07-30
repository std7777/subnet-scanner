import java.net.InetAddress;
import java.net.UnknownHostException;

public class ScanConfig {

    public final InetAddress networkAddress;
    public final int prefixLength;
    public final int startPort = 1;
    public final int endPort = 1000;
    public final int connectTimeoutMs = 800;
    public final int readTimeoutMs = 300;
    public final int rateLimitPerSecond = 400;

    private ScanConfig(InetAddress networkAddress, int prefixLength) {
        this.networkAddress = networkAddress;
        this.prefixLength = prefixLength;
    }

    public static ScanConfig fromCidr(String cidr) {
        if (cidr == null) {
            throw new IllegalArgumentException("Invalid CIDR format");
        }

        String[] parts = cidr.split("/", -1);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid CIDR format");
        }

        int prefix;
        try {
            prefix = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid prefix length");
        }

        if (prefix < 16) {
            throw new IllegalArgumentException("Subnet larger than /16 not allowed");
        }

        if (prefix > 32) {
            throw new IllegalArgumentException("Invalid prefix length");
        }

        long address = parseIpv4(parts[0]);
        long mask = (0xffffffffL << (32 - prefix)) & 0xffffffffL;
        long network = address & mask;

        return new ScanConfig(toInetAddress(network), prefix);
    }

    public long totalAddressCount() {
        return 1L << (32 - prefixLength);
    }

    public long firstHostOffset() {
        return prefixLength <= 30 ? 1 : 0;
    }

    public long scanHostCount() {
        long totalAddresses = totalAddressCount();
        return prefixLength <= 30 ? totalAddresses - 2 : totalAddresses;
    }

    private static long parseIpv4(String input) {
        String[] octets = input.split("\\.", -1);
        if (octets.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address");
        }

        long address = 0;
        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3) {
                throw new IllegalArgumentException("Invalid IPv4 address");
            }

            for (int i = 0; i < octet.length(); i++) {
                if (!Character.isDigit(octet.charAt(i))) {
                    throw new IllegalArgumentException("Invalid IPv4 address");
                }
            }

            int value;
            try {
                value = Integer.parseInt(octet);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid IPv4 address");
            }

            if (value > 255) {
                throw new IllegalArgumentException("Invalid IPv4 address");
            }

            address = (address << 8) | value;
        }

        return address;
    }

    private static InetAddress toInetAddress(long address) {
        byte[] octets = new byte[] {
                (byte) ((address >> 24) & 0xff),
                (byte) ((address >> 16) & 0xff),
                (byte) ((address >> 8) & 0xff),
                (byte) (address & 0xff)
        };

        try {
            return InetAddress.getByAddress(octets);
        } catch (UnknownHostException e) {
            throw new IllegalStateException("Failed to create IPv4 network address", e);
        }
    }
}
