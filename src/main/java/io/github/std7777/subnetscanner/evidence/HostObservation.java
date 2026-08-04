package io.github.std7777.subnetscanner.evidence;

import java.time.Instant;
import java.util.Map;

public record HostObservation(
        Instant observedAt,
        String address,
        String hostname,
        HostState state,
        Map<String, String> attributes
) {
    public HostObservation {
        observedAt = EvidenceValidation.require(observedAt, "observedAt");
        address = EvidenceValidation.requireText(address, "address");
        hostname = EvidenceValidation.optionalText(hostname, "hostname");
        state = EvidenceValidation.require(state, "state");
        attributes = EvidenceValidation.immutableAttributes(attributes);
    }
}
