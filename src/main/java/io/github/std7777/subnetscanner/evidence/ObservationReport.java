package io.github.std7777.subnetscanner.evidence;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public record ObservationReport(
        String schemaVersion,
        UUID observationId,
        ObservationMode mode,
        ObservationStatus status,
        Instant startedAt,
        Instant finishedAt,
        Observer observer,
        ObservationTarget target,
        List<HostObservation> hosts,
        List<PortObservation> observations,
        List<ObservationError> errors,
        Map<String, String> metadata
) {
    public ObservationReport {
        schemaVersion = EvidenceValidation.requireText(schemaVersion, "schemaVersion");
        observationId = EvidenceValidation.require(observationId, "observationId");
        mode = EvidenceValidation.require(mode, "mode");
        status = EvidenceValidation.require(status, "status");
        startedAt = EvidenceValidation.require(startedAt, "startedAt");
        finishedAt = EvidenceValidation.require(finishedAt, "finishedAt");
        observer = EvidenceValidation.require(observer, "observer");
        target = EvidenceValidation.require(target, "target");

        if (finishedAt.isBefore(startedAt)) {
            throw new IllegalArgumentException("finishedAt must not be before startedAt");
        }

        hosts = EvidenceValidation.immutableList(hosts);
        observations = EvidenceValidation.immutableList(observations);
        errors = EvidenceValidation.immutableList(errors);
        metadata = EvidenceValidation.immutableAttributes(metadata);
    }
}
