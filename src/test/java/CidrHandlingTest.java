import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CidrHandlingTest {

    @Test
    void normalizesHostAddressToNetwork() {
        ScanConfig config = ScanConfig.fromCidr("192.168.1.100/24");

        assertEquals("192.168.1.0", config.networkAddress.getHostAddress());
        assertEquals(256L, config.totalAddressCount());
        assertEquals(1L, config.firstHostOffset());
        assertEquals(254L, config.scanHostCount());
    }

    @Test
    void handlesPointToPointNetwork() {
        ScanConfig config = ScanConfig.fromCidr("10.0.0.11/31");

        assertEquals("10.0.0.10", config.networkAddress.getHostAddress());
        assertEquals(2L, config.totalAddressCount());
        assertEquals(0L, config.firstHostOffset());
        assertEquals(2L, config.scanHostCount());
    }

    @Test
    void handlesSingleHostNetwork() {
        ScanConfig config = ScanConfig.fromCidr("10.0.0.11/32");

        assertEquals("10.0.0.11", config.networkAddress.getHostAddress());
        assertEquals(1L, config.totalAddressCount());
        assertEquals(0L, config.firstHostOffset());
        assertEquals(1L, config.scanHostCount());
    }

    @Test
    void rejectsNonIpv4Targets() {
        assertRejected("localhost/32");
        assertRejected("::1/32");
    }

    @Test
    void rejectsMalformedTargets() {
        assertRejected("192.168.1.256/24");
        assertRejected("192.168.1/24");
        assertRejected("192.168.1.1/");
        assertRejected("192.168.1.1/not-a-prefix");
        assertRejected("192.168.1.1/15");
        assertRejected("192.168.1.1/33");
    }

    private static void assertRejected(String cidr) {
        assertThrows(IllegalArgumentException.class, () -> ScanConfig.fromCidr(cidr));
    }
}
