package io.github.std7777.subnetscanner.evidence;

import java.util.List;
import java.util.Map;

public record Observer(
        String id,
        String hostname,
        List<String> addresses,
        VantagePoint vantagePoint,
        Map<String, String> attributes
) {
    public Observer {
        id = EvidenceValidation.requireText(id, "id");
        hostname = EvidenceValidation.optionalText(hostname, "hostname");
        addresses = EvidenceValidation.immutableList(addresses);
        vantagePoint = EvidenceValidation.require(vantagePoint, "vantagePoint");
        attributes = EvidenceValidation.immutableAttributes(attributes);
    }
}
