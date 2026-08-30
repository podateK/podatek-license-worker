package dev.podatek.worker;

import java.util.LinkedHashMap;
import java.util.Map;

/** The license config from a /inject request. Mirrors Plan 3's GeneratedConfig fields. */
public record InjectConfig(
        String baseUrl,
        String pluginId,
        Map<String, String> publicKeys,
        String activeKeyId,
        String licenseKeyFileName) {

    public InjectConfig {
        // Defensive copy so callers cannot mutate after construction.
        publicKeys = publicKeys == null ? Map.of() : new LinkedHashMap<>(publicKeys);
    }
}
