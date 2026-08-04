import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.github.std7777.subnetscanner.evidence.EvidenceSchema;
import io.github.std7777.subnetscanner.evidence.ObservationMode;
import io.github.std7777.subnetscanner.evidence.ObservationReport;
import io.github.std7777.subnetscanner.evidence.ObservationStatus;
import io.github.std7777.subnetscanner.evidence.ObservationTarget;
import io.github.std7777.subnetscanner.evidence.Observer;
import io.github.std7777.subnetscanner.evidence.TargetType;
import io.github.std7777.subnetscanner.evidence.VantagePoint;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JsonSerializerTest {

    @Test
    void serializesStructuredEvidenceAsValidJson() throws Exception {
        ObservationReport report = new ObservationReport(
                EvidenceSchema.CURRENT_VERSION,
                UUID.fromString("d739bfbd-dc5c-4e4f-91f2-5eb19a05f80e"),
                ObservationMode.PROBE_SERVICE,
                ObservationStatus.COMPLETED,
                Instant.parse("2026-08-02T10:00:00Z"),
                Instant.parse("2026-08-02T10:00:01Z"),
                new Observer("agent-1", null, List.of(), VantagePoint.LOCAL_HOST, Map.of()),
                new ObservationTarget(TargetType.SERVICE, "127.0.0.1:443", Map.of()),
                List.of(),
                List.of(),
                List.of(),
                Map.of("message", "line one\nline two")
        );

        JsonNode json = JsonMapper.builder().build().readTree(JsonSerializer.toJson(report));

        assertEquals("1.0", json.get("schemaVersion").asText());
        assertEquals("line one\nline two", json.get("metadata").get("message").asText());
        assertEquals("2026-08-02T10:00:00Z", json.get("startedAt").asText());
    }
}
