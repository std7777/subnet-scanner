package io.github.std7777.subnetscanner.evidence;

import java.util.List;
import java.util.Map;
import java.util.Objects;

final class EvidenceValidation {

    private EvidenceValidation() {
    }

    static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value;
    }

    static String optionalText(String value, String fieldName) {
        if (value != null && value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank when provided");
        }
        return value;
    }

    static <T> T require(T value, String fieldName) {
        return Objects.requireNonNull(value, fieldName + " must not be null");
    }

    static <T> List<T> immutableList(List<T> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    static Map<String, String> immutableAttributes(Map<String, String> attributes) {
        return attributes == null ? Map.of() : Map.copyOf(attributes);
    }
}
