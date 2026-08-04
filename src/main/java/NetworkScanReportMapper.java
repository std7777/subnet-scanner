import io.github.std7777.subnetscanner.evidence.EvidenceSchema;
import io.github.std7777.subnetscanner.evidence.HostObservation;
import io.github.std7777.subnetscanner.evidence.HostState;
import io.github.std7777.subnetscanner.evidence.IdentificationSource;
import io.github.std7777.subnetscanner.evidence.ObservationMode;
import io.github.std7777.subnetscanner.evidence.ObservationReport;
import io.github.std7777.subnetscanner.evidence.ObservationStatus;
import io.github.std7777.subnetscanner.evidence.ObservationTarget;
import io.github.std7777.subnetscanner.evidence.Observer;
import io.github.std7777.subnetscanner.evidence.PortObservation;
import io.github.std7777.subnetscanner.evidence.PortState;
import io.github.std7777.subnetscanner.evidence.ServiceEvidence;
import io.github.std7777.subnetscanner.evidence.TargetType;
import io.github.std7777.subnetscanner.evidence.TransportProtocol;
import io.github.std7777.subnetscanner.evidence.VantagePoint;

import java.net.InetAddress;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class NetworkScanReportMapper {

    private NetworkScanReportMapper() {
    }

    public static ObservationReport from(
            ScanReport legacyReport,
            ScanConfig config,
            Instant startedAt
    ) {
        Instant finishedAt = Instant.parse(legacyReport.scanTimestamp);
        List<HostObservation> hosts = new ArrayList<>();
        List<PortObservation> ports = new ArrayList<>();

        for (HostReport host : legacyReport.hosts) {
            hosts.add(new HostObservation(
                    finishedAt,
                    host.ip,
                    null,
                    HostState.REACHABLE,
                    Map.of()
            ));

            for (ScanResult result : host.ports) {
                ports.add(new PortObservation(
                        finishedAt,
                        host.ip,
                        null,
                        TransportProtocol.TCP,
                        result.port,
                        PortState.OPEN,
                        null,
                        null,
                        null,
                        null,
                        serviceEvidence(result),
                        Map.of()
                ));
            }
        }

        return new ObservationReport(
                EvidenceSchema.CURRENT_VERSION,
                UUID.randomUUID(),
                ObservationMode.SCAN_NETWORK,
                ObservationStatus.COMPLETED,
                startedAt,
                finishedAt,
                localObserver(),
                new ObservationTarget(TargetType.CIDR, config.networkAddress.getHostAddress() + "/" + config.prefixLength, Map.of()),
                hosts,
                ports,
                List.of(),
                Map.of(
                        "connectTimeoutMs", String.valueOf(config.connectTimeoutMs),
                        "portRange", config.startPort + "-" + config.endPort,
                        "readTimeoutMs", String.valueOf(config.readTimeoutMs),
                        "transport", "tcp"
                )
        );
    }

    private static ServiceEvidence serviceEvidence(ScanResult result) {
        if ("unknown".equals(result.service)) {
            return null;
        }

        return new ServiceEvidence(
                result.service,
                IdentificationSource.PORT_MAPPING,
                0.5,
                result.banner,
                null,
                Map.of()
        );
    }

    private static Observer localObserver() {
        try {
            InetAddress localAddress = InetAddress.getLocalHost();
            return new Observer(
                    "network-scan-agent",
                    localAddress.getHostName(),
                    List.of(localAddress.getHostAddress()),
                    VantagePoint.INTERNAL_NETWORK,
                    Map.of("collector", "subnet-scanner")
            );
        } catch (Exception ignored) {
            return new Observer(
                    "network-scan-agent",
                    null,
                    List.of(),
                    VantagePoint.INTERNAL_NETWORK,
                    Map.of("collector", "subnet-scanner")
            );
        }
    }
}
