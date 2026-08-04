package io.github.std7777.subnetscanner.evidence;

import java.util.Map;

public record ProcessEvidence(
        Long pid,
        String name,
        String executablePath,
        String user,
        String containerId,
        Map<String, String> attributes
) {
    public ProcessEvidence {
        if (pid != null && pid <= 0) {
            throw new IllegalArgumentException("pid must be greater than zero when provided");
        }

        name = EvidenceValidation.optionalText(name, "name");
        executablePath = EvidenceValidation.optionalText(executablePath, "executablePath");
        user = EvidenceValidation.optionalText(user, "user");
        containerId = EvidenceValidation.optionalText(containerId, "containerId");
        attributes = EvidenceValidation.immutableAttributes(attributes);
    }
}
