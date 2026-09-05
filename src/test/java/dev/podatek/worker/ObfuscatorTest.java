package dev.podatek.worker;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ObfuscatorTest {

    private static final String PFX = "p1234";
    private static final byte[] SALT = {0x11, 0x42, (byte) 0x9c, 0x07, 0x5b, (byte) 0xa3, 0x2f, 0x60};

    /**
     * Plaintext that MUST NOT survive: the panel URL, the request endpoints, and the Polish
     * user-facing messages that reveal the license logic. NOT enum-constant tokens (REVOKED,
     * LIMIT_REACHED, ...): those are structural field identifiers that double as wire values —
     * hiding them needs name-mangling (deferred) + a protocol change, out of Layer 1 scope.
     */
    private static final String[] LEAKS = {
            "https://license.podatek.dev",
            "/activate", "/heartbeat", "/deactivate",
            "PDTK",
            "Licencja:", "klucz licencyjny", "zrestartuj serwer",
            "nieprawidlowy", "wygasla", "zablokowana", "cofniety", "polaczenia z serwerem",
    };

    private static Map<String, byte[]> obfuscatedPayload() {
        Map<String, byte[]> reloc = Relocator.relocate(ClientPayload.classes(), PFX);
        return Obfuscator.obfuscate(reloc, PFX, SALT);
    }

    @Test void stripsPlaintextFromOurClasses() {
        Map<String, byte[]> obf = obfuscatedPayload();
        for (Map.Entry<String, byte[]> e : obf.entrySet()) {
            String key = e.getKey();
            if (!key.startsWith(PFX + "/")) continue;
            if (key.startsWith(PFX + "/shaded/")) continue;
            String raw = new String(e.getValue(), StandardCharsets.ISO_8859_1);
            for (String leak : LEAKS) {
                assertFalse(raw.contains(leak),
                        "plaintext leak '" + leak + "' still present in " + key);
            }
        }
    }

    @Test void shadedCryptoLibIsUntouched() {
        Map<String, byte[]> reloc = Relocator.relocate(ClientPayload.classes(), PFX);
        Map<String, byte[]> obf = Obfuscator.obfuscate(reloc, PFX, SALT);
        for (String k : reloc.keySet()) {
            if (k.startsWith(PFX + "/shaded/")) {
                assertArrayEquals(reloc.get(k), obf.get(k), "shaded lib class was modified: " + k);
            }
        }
    }

    @Test void decodedStringsRoundTripAtRuntime() throws Exception {
        String methodStr = "Licencja: tajny komunikat operacyjny";
        String fieldStr = "https://secret.example/panel";

        Map<String, byte[]> in = new LinkedHashMap<>();
        in.put(PFX + "/Sample.class", sampleClass(PFX + "/Sample", methodStr, fieldStr));
        Map<String, byte[]> obf = Obfuscator.obfuscate(in, PFX, SALT);

        // plaintext gone from Sample (both method LDC and the ConstantValue field)
        String raw = new String(obf.get(PFX + "/Sample.class"), StandardCharsets.ISO_8859_1);
        assertFalse(raw.contains(methodStr), "method-body string leaked");
        assertFalse(raw.contains(fieldStr), "ConstantValue field string leaked");

        // ...but the runtime values are identical after decode
        TestClassLoaders.ByteArrayClassLoader cl = TestClassLoaders.loader(obf);
        Class<?> sample = Class.forName(PFX + ".Sample", true, cl);
        assertEquals(methodStr, sample.getMethod("msg").invoke(null));
        assertEquals(fieldStr, sample.getMethod("url").invoke(null));
        assertEquals(fieldStr, sample.getField("URL").get(null));
    }

    /** Synthesized class: a ConstantValue String field + two getters, one via LDC, one via GETSTATIC. */
    private static byte[] sampleClass(String internal, String methodStr, String fieldStr) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                internal, null, "java/lang/Object", null);
        cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "URL", "Ljava/lang/String;", null, fieldStr).visitEnd();

        MethodVisitor msg = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "msg",
                "()Ljava/lang/String;", null, null);
        msg.visitCode();
        msg.visitLdcInsn(methodStr);
        msg.visitInsn(Opcodes.ARETURN);
        msg.visitMaxs(0, 0);
        msg.visitEnd();

        MethodVisitor url = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "url",
                "()Ljava/lang/String;", null, null);
        url.visitCode();
        url.visitFieldInsn(Opcodes.GETSTATIC, internal, "URL", "Ljava/lang/String;");
        url.visitInsn(Opcodes.ARETURN);
        url.visitMaxs(0, 0);
        url.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }
}
