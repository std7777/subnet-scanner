package io.github.std7777.subnetscanner.evidence;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EvidenceModelTest {

    @Test
    void representsNeutralEvidenceFromADeclaredVantagePoint() {
        Instant startedAt = Instant.parse("2026-07-30T12:00:00Z");
        Instant finishedAt = startedAt.plusSeconds(2);

        ProcessEvidence process = new ProcessEvidence(
                1421L,
                "mysqld",
                "/usr/sbin/mysqld",
                "mysql",
                null,
                Map.of("socketInode", "9012")
        );

        ServiceEvidence service = new ServiceEvidence(
                "mysql",
                IdentificationSource.PROCESS_METADATA,
                0.95,
                null,
                null,
                Map.of()
        );

        PortObservation port = new PortObservation(
                finishedAt,
                "10.0.0.5",
                "db-01",
                TransportProtocol.TCP,
                3306,
                PortState.LISTENING,
                "0.0.0.0",
                "eth0",
                null,
                process,
                service,
                Map.of()
        );

        ObservationReport report = new ObservationReport(
                EvidenceSchema.CURRENT_VERSION,
                UUID.fromString("9c41ec8c-8155-4c55-a866-feb97df818f4"),
                ObservationMode.OBSERVE_LOCAL,
                ObservationStatus.COMPLETED,
                startedAt,
                finishedAt,
                new Observer(
                        "agent-db-01",
                        "db-01",
                        List.of("10.0.0.5"),
                        VantagePoint.LOCAL_HOST,
                        Map.of()
                ),
                new ObservationTarget(TargetType.LOCAL_HOST, "db-01", Map.of()),
                List.of(),
                List.of(port),
                List.of(),
                Map.of("collector", "local-socket-observer")
        );

        assertEquals("1.0", report.schemaVersion());
        assertEquals(ObservationMode.OBSERVE_LOCAL, report.mode());
        assertEquals(PortState.LISTENING, report.observations().getFirst().state());
        assertEquals("mysqld", report.observations().getFirst().process().name());
        assertEquals(0.95, report.observations().getFirst().service().confidence());
    }

    @Test
    void defensivelyCopiesCollections() {
        List<String> addresses = new ArrayList<>(List.of("10.0.0.5"));
        Map<String, String> attributes = new HashMap<>(Map.of("zone", "internal"));

        Observer observer = new Observer(
                "agent-1",
                null,
                addresses,
                VantagePoint.INTERNAL_NETWORK,
                attributes
        );

        addresses.add("10.0.0.6");
        attributes.put("changed", "true");

        assertEquals(List.of("10.0.0.5"), observer.addresses());
        assertEquals(Map.of("zone", "internal"), observer.attributes());
        assertThrows(UnsupportedOperationException.class,
                () -> observer.addresses().add("10.0.0.7"));
        assertThrows(UnsupportedOperationException.class,
                () -> observer.attributes().put("new", "value"));
    }

    @Test
    void rejectsInvalidPortAndLatency() {
        Instant now = Instant.parse("2026-07-30T12:00:00Z");

        assertThrows(IllegalArgumentException.class, () -> new PortObservation(
                now, "10.0.0.5", null, TransportProtocol.TCP, 0,
                PortState.OPEN, null, null, null, null, null, Map.of()
        ));

        assertThrows(IllegalArgumentException.class, () -> new PortObservation(
                now, "10.0.0.5", null, TransportProtocol.TCP, 443,
                PortState.OPEN, null, null, -1L, null, null, Map.of()
        ));
    }

    @Test
    void rejectsInvalidConfidence() {
        assertThrows(IllegalArgumentException.class, () -> new ServiceEvidence(
                "https", IdentificationSource.TLS_HANDSHAKE, 1.1,
                null, null, Map.of()
        ));
    }

    @Test
    void rejectsReversedReportTimestamps() {
        Instant startedAt = Instant.parse("2026-07-30T12:00:01Z");
        Instant finishedAt = startedAt.minusSeconds(1);

        assertThrows(IllegalArgumentException.class, () -> new ObservationReport(
                EvidenceSchema.CURRENT_VERSION,
                UUID.randomUUID(),
                ObservationMode.SCAN_NETWORK,
                ObservationStatus.COMPLETED,
                startedAt,
                finishedAt,
                new Observer(
                        "scanner-1",
                        null,
                        List.of(),
                        VantagePoint.INTERNAL_NETWORK,
                        Map.of()
                ),
                new ObservationTarget(TargetType.CIDR, "10.0.0.0/24", Map.of()),
                List.of(),
                List.of(),
                List.of(),
                Map.of()
        ));
    }

    @Test
    void rejectsReversedCertificateValidity() {
        Instant validFrom = Instant.parse("2026-07-30T12:00:01Z");
        Instant validUntil = validFrom.minusSeconds(1);

        assertThrows(IllegalArgumentException.class, () -> new TlsEvidence(
                "TLSv1.3",
                "TLS_AES_128_GCM_SHA256",
                null,
                null,
                null,
                validFrom,
                validUntil,
                List.of(),
                Map.of()
        ));
    }

    @Test
    void convertsMissingCollectionsToEmptyImmutableCollections() {
        Observer observer = new Observer(
                "agent-1",
                null,
                null,
                VantagePoint.UNSPECIFIED,
                null
        );

        assertEquals(List.of(), observer.addresses());
        assertEquals(Map.of(), observer.attributes());
    }
}
