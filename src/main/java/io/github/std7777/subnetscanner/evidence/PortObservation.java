package io.github.std7777.subnetscanner.evidence;

import java.time.Instant;
import java.util.Map;

public record PortObservation(
        Instant observedAt,
        String address,
        String hostname,
        TransportProtocol protocol,
        int port,
        PortState state,
        String bindAddress,
        String interfaceName,
        Long latencyMillis,
        ProcessEvidence process,
        ServiceEvidence service,
        Map<String, String> attributes
) {
    public PortObservation {
        observedAt = EvidenceValidation.require(observedAt, "observedAt");
        address = EvidenceValidation.requireText(address, "address");
        hostname = EvidenceValidation.optionalText(hostname, "hostname");
        protocol = EvidenceValidation.require(protocol, "protocol");

        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException("port must be between 1 and 65535");
        }

        state = EvidenceValidation.require(state, "state");
        bindAddress = EvidenceValidation.optionalText(bindAddress, "bindAddress");
        interfaceName = EvidenceValidation.optionalText(interfaceName, "interfaceName");

        if (latencyMillis != null && latencyMillis < 0) {
            throw new IllegalArgumentException("latencyMillis must not be negative");
        }

        attributes = EvidenceValidation.immutableAttributes(attributes);
    }
}
