import io.github.std7777.subnetscanner.evidence.IdentificationSource;
import io.github.std7777.subnetscanner.evidence.ObservationMode;
import io.github.std7777.subnetscanner.evidence.ObservationReport;
import io.github.std7777.subnetscanner.evidence.PortState;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class NetworkScanReportMapperTest {

    @Test
    void mapsLegacyNetworkResultsToNeutralEvidence() {
        ScanReport legacy = new ScanReport(
                "2026-08-02T10:00:02Z",
                List.of(
                        new HostReport("10.0.0.5", List.of(
                                new ScanResult(22, "ssh", "SSH-2.0-OpenSSH"),
                                new ScanResult(999, "unknown", null)
                        )),
                        new HostReport("10.0.0.6", List.of())
                )
        );

        ObservationReport report = NetworkScanReportMapper.from(
                legacy,
                ScanConfig.fromCidr("10.0.0.5/24"),
                Instant.parse("2026-08-02T10:00:00Z")
        );

        assertEquals(ObservationMode.SCAN_NETWORK, report.mode());
        assertEquals("10.0.0.0/24", report.target().value());
        assertEquals(2, report.hosts().size());
        assertEquals(2, report.observations().size());
        assertEquals(PortState.OPEN, report.observations().getFirst().state());
        assertEquals(IdentificationSource.PORT_MAPPING,
                report.observations().getFirst().service().identificationSource());
        assertNull(report.observations().get(1).service());
        assertEquals("1-1000", report.metadata().get("portRange"));
    }
}
