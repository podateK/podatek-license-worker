package dev.podatek.worker;

import org.jetbrains.java.decompiler.main.decompiler.ConsoleDecompiler;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Proves the goal: a decompiler (Vineflower — maintained FernFlower fork, same package) recovers
 * NO readable license logic from our obfuscated classes. If Vineflower can't read it, FernFlower
 * (weaker) can't either.
 */
class DecompileResistanceTest {

    private static final String PFX = "p1234";
    private static final byte[] SALT = {0x11, 0x42, (byte) 0x9c, 0x07, 0x5b, (byte) 0xa3, 0x2f, 0x60};

    @Test void obfuscatedClassesDoNotDecompileToPlaintext() throws Exception {
        Map<String, byte[]> reloc = Relocator.relocate(ClientPayload.classes(), PFX);
        Map<String, byte[]> obf = Obfuscator.obfuscate(reloc, PFX, SALT);

        Path in = Files.createTempDirectory("obf-in");
        Path out = Files.createTempDirectory("obf-out");
        // Dump all our non-shaded logic classes so cross-references resolve during decompile.
        for (Map.Entry<String, byte[]> e : obf.entrySet()) {
            String key = e.getKey();
            if (!key.endsWith(".class")) continue;
            if (!key.startsWith(PFX + "/")) continue;
            if (key.startsWith(PFX + "/shaded/")) continue;
            Path dst = in.resolve(key);
            Files.createDirectories(dst.getParent());
            Files.write(dst, e.getValue());
        }

        ConsoleDecompiler.main(new String[]{in.toAbsolutePath().toString(), out.toAbsolutePath().toString()});

        String enforcer = readDecompiled(out, "LicenseEnforcer.java");
        assertNotNull(enforcer, "LicenseEnforcer.java was not produced by the decompiler");

        // The whole point: no readable URL / user messages in decompiled source.
        for (String leak : new String[]{
                "https://license.podatek.dev", "Licencja:", "klucz licencyjny",
                "zrestartuj serwer", "polaczenia z serwerem"}) {
            assertFalse(enforcer.contains(leak),
                    "decompiled LicenseEnforcer still shows plaintext: '" + leak + "'");
        }
        // Instead, strings appear as opaque byte arrays decoded via the holder call.
        assertTrue(enforcer.contains("new byte[]") || enforcer.contains("byte[]"),
                "expected encrypted byte[] literals in decompiled source");
        assertTrue(enforcer.contains(".d("),
                "expected runtime decoder call K.d(...) in decompiled source");
    }

    private static String readDecompiled(Path outDir, String fileSuffix) throws Exception {
        try (Stream<Path> s = Files.walk(outDir)) {
            Path f = s.filter(p -> p.getFileName().toString().equals(fileSuffix)).findFirst().orElse(null);
            if (f == null) return null;
            return new String(Files.readAllBytes(f), StandardCharsets.UTF_8);
        }
    }
}
