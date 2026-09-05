package dev.podatek.worker;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.BasicVerifier;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Hard loadability gate: EVERY emitted class of a real obfuscated payload must pass ASM's
 * BasicVerifier data-flow analysis. This is exactly the check that catches frames the real HotSpot
 * verifier rejects (e.g. reading an uninitialized/Top local — the production activateNow VerifyError)
 * without needing a bukkit/Paper runtime. If flattening ever emits such a frame again, this fails.
 */
class ObfuscatorVerifyGateTest {

    private static final String PFX = "p1234";
    private static final byte[] SALT = {0x11, 0x42, (byte) 0x9c, 0x07, 0x5b, (byte) 0xa3, 0x2f, 0x60};

    @Test void everyObfuscatedClassPassesRealDataFlowVerification() throws Exception {
        Map<String, byte[]> obf =
                Obfuscator.obfuscate(Relocator.relocate(ClientPayload.classes(), PFX), PFX, SALT);

        StringBuilder failures = new StringBuilder();
        for (Map.Entry<String, byte[]> e : obf.entrySet()) {
            if (!e.getKey().endsWith(".class")) continue;
            ClassNode cn = new ClassNode();
            new ClassReader(e.getValue()).accept(cn, 0);
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                try {
                    new Analyzer<BasicValue>(new BasicVerifier()).analyze(cn.name, mn);
                } catch (Throwable t) {
                    failures.append("\n  ").append(cn.name).append('.').append(mn.name).append(mn.desc)
                            .append(" -> ").append(t.getMessage());
                }
            }
        }
        if (failures.length() > 0) {
            fail("obfuscated classes failed BasicVerifier (would VerifyError on a real JVM):" + failures);
        }
    }
}
