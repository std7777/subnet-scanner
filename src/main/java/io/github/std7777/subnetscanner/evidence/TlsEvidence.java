package io.github.std7777.subnetscanner.evidence;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record TlsEvidence(
        String protocol,
        String cipherSuite,
        String certificateSha256,
        String subject,
        String issuer,
        Instant validFrom,
        Instant validUntil,
        List<String> subjectAlternativeNames,
        Map<String, String> attributes
) {
    public TlsEvidence {
        protocol = EvidenceValidation.optionalText(protocol, "protocol");
        cipherSuite = EvidenceValidation.optionalText(cipherSuite, "cipherSuite");
        certificateSha256 = EvidenceValidation.optionalText(certificateSha256, "certificateSha256");
        subject = EvidenceValidation.optionalText(subject, "subject");
        issuer = EvidenceValidation.optionalText(issuer, "issuer");

        if (validFrom != null && validUntil != null && validUntil.isBefore(validFrom)) {
            throw new IllegalArgumentException("validUntil must not be before validFrom");
        }

        subjectAlternativeNames = EvidenceValidation.immutableList(subjectAlternativeNames);
        attributes = EvidenceValidation.immutableAttributes(attributes);
    }
}
