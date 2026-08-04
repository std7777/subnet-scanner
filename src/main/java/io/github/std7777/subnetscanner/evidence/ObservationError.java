package io.github.std7777.subnetscanner.evidence;

import java.time.Instant;
import java.util.Map;

public record ObservationError(
        Instant occurredAt,
        String code,
        String message,
        String address,
        Integer port,
        boolean retryable,
        Map<String, String> attributes
) {
    public ObservationError {
        occurredAt = EvidenceValidation.require(occurredAt, "occurredAt");
        code = EvidenceValidation.requireText(code, "code");
        message = EvidenceValidation.requireText(message, "message");
        address = EvidenceValidation.optionalText(address, "address");

        if (port != null && (port < 1 || port > 65_535)) {
            throw new IllegalArgumentException("port must be between 1 and 65535 when provided");
        }

        attributes = EvidenceValidation.immutableAttributes(attributes);
    }
}
