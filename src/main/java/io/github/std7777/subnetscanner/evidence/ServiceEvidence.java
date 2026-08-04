package io.github.std7777.subnetscanner.evidence;

import java.util.Map;

public record ServiceEvidence(
        String name,
        IdentificationSource identificationSource,
        double confidence,
        String banner,
        TlsEvidence tls,
        Map<String, String> attributes
) {
    public ServiceEvidence {
        name = EvidenceValidation.requireText(name, "name");
        identificationSource = EvidenceValidation.require(identificationSource, "identificationSource");

        if (!Double.isFinite(confidence) || confidence < 0.0 || confidence > 1.0) {
            throw new IllegalArgumentException("confidence must be between 0.0 and 1.0");
        }

        attributes = EvidenceValidation.immutableAttributes(attributes);
    }
}
