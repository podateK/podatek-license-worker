package dev.podatek.worker;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static dev.podatek.worker.TestClassLoaders.field;
import static dev.podatek.worker.TestClassLoaders.invokeStaticLoad;
import static org.junit.jupiter.api.Assertions.*;

class ConfigEmitterTest {

    @Test void emittedLoadReturnsInjectedValues() throws Exception {
        String prefix = "p9";
        Map<String, byte[]> payload = Relocator.relocate(ClientPayload.classes(), prefix);
        InjectConfig cfg = new InjectConfig("https://auth4.podatek.dev/api/license", "demo",
                Map.of("k1", "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="), "k1", "license.key");
        byte[] gc = ConfigEmitter.emit(prefix, cfg, new byte[]{1, 2, 3, 4});
        assertEquals(52, ((gc[6] & 0xFF) << 8) | (gc[7] & 0xFF), "major version must be 52");
        // With a salt, string constants must be obfuscated: plaintext URL absent from bytes.
        String raw = new String(gc, java.nio.charset.StandardCharsets.ISO_8859_1);
        assertFalse(raw.contains("auth4.podatek.dev"), "baseUrl must not appear in plaintext");

        Map<String, byte[]> all = new HashMap<>(payload);
        all.put(prefix + "/GeneratedConfig", gc);
        Object loaded = invokeStaticLoad(all, prefix + ".GeneratedConfig");

        assertEquals("https://auth4.podatek.dev/api/license", field(loaded, "baseUrl"));
        assertEquals("demo", field(loaded, "pluginId"));
        assertEquals("k1", field(loaded, "activeKeyId"));
        assertEquals("license.key", field(loaded, "licenseKeyFileName"));
        @SuppressWarnings("unchecked")
        Map<String, String> keys = (Map<String, String>) field(loaded, "publicKeys");
        assertEquals("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=", keys.get("k1"));
    }
}
