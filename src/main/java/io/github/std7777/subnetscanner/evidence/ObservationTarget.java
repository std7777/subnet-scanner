package io.github.std7777.subnetscanner.evidence;

import java.util.Map;

public record ObservationTarget(
        TargetType type,
        String value,
        Map<String, String> attributes
) {
    public ObservationTarget {
        type = EvidenceValidation.require(type, "type");
        value = EvidenceValidation.requireText(value, "value");
        attributes = EvidenceValidation.immutableAttributes(attributes);
    }
}
