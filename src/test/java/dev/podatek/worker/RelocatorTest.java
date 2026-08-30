package dev.podatek.worker;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RelocatorTest {

    @Test void relocatesEveryClientClass() {
        Map<String, byte[]> payload = ClientPayload.classes();
        assertFalse(payload.isEmpty());
        assertTrue(payload.keySet().stream().anyMatch(k -> k.endsWith("PodatekLicense.class")));

        Map<String, byte[]> out = Relocator.relocate(payload, "p1234");
        assertTrue(out.keySet().stream().allMatch(k -> k.startsWith("p1234/")));
        assertTrue(out.keySet().stream().anyMatch(k -> k.endsWith("PodatekLicense.class")));
        assertEquals(payload.size(), out.size());

        // no lingering dev/podatek/lic references (slash form) in any class bytes
        for (byte[] b : out.values()) {
            String s = new String(b, StandardCharsets.ISO_8859_1);
            assertFalse(s.contains("dev/podatek/lic"), "slash-form base package leaked");
            assertFalse(s.contains("dev.podatek.lic"), "dotted base package leaked");
        }
    }
}
