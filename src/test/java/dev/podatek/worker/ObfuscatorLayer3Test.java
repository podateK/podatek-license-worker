package dev.podatek.worker;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ObfuscatorLayer3Test {

    private static final String PFX = "p1234";
    private static final byte[] SALT = {0x11, 0x42, (byte) 0x9c, 0x07, 0x5b, (byte) 0xa3, 0x2f, 0x60};

    private static boolean hasSwitch(byte[] cls, String method) {
        ClassNode cn = new ClassNode();
        new ClassReader(cls).accept(cn, 0);
        for (MethodNode mn : cn.methods) {
            if (!mn.name.equals(method)) continue;
            for (AbstractInsnNode in = mn.instructions.getFirst(); in != null; in = in.getNext())
                if (in instanceof LookupSwitchInsnNode || in instanceof TableSwitchInsnNode) return true;
        }
        return false;
    }

    /** classify(int): three-way branch, stable locals (only the int param) -> CFF-eligible. */
    private static byte[] sample(String internal) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                internal, null, "java/lang/Object", null);
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "classify", "(I)I", null, null);
        m.visitCode();
        Label notNeg = new Label();
        Label notZero = new Label();
        m.visitVarInsn(Opcodes.ILOAD, 0);
        m.visitJumpInsn(Opcodes.IFGE, notNeg);
        m.visitInsn(Opcodes.ICONST_M1);
        m.visitInsn(Opcodes.IRETURN);
        m.visitLabel(notNeg);
        m.visitVarInsn(Opcodes.ILOAD, 0);
        m.visitJumpInsn(Opcodes.IFNE, notZero);
        m.visitInsn(Opcodes.ICONST_0);
        m.visitInsn(Opcodes.IRETURN);
        m.visitLabel(notZero);
        m.visitInsn(Opcodes.ICONST_1);
        m.visitInsn(Opcodes.IRETURN);
        m.visitMaxs(0, 0);
        m.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    @Test void flattensControlFlowButPreservesSemantics() throws Exception {
        byte[] before = sample(PFX + "/C");
        assertFalse(hasSwitch(before, "classify"), "sample should start without a switch");

        Map<String, byte[]> in = new LinkedHashMap<>();
        in.put(PFX + "/C.class", before);
        Map<String, byte[]> obf = Obfuscator.obfuscate(in, PFX, SALT);

        assertTrue(hasSwitch(obf.get(PFX + "/C.class"), "classify"),
                "expected control-flow flattened into a switch dispatcher");

        TestClassLoaders.ByteArrayClassLoader cl = TestClassLoaders.loader(obf);
        Class<?> c = Class.forName(PFX + ".C", true, cl);
        assertEquals(-1, c.getMethod("classify", int.class).invoke(null, -5));
        assertEquals(0, c.getMethod("classify", int.class).invoke(null, 0));
        assertEquals(1, c.getMethod("classify", int.class).invoke(null, 42));
        assertEquals(-1, c.getMethod("classify", int.class).invoke(null, Integer.MIN_VALUE));
        assertEquals(1, c.getMethod("classify", int.class).invoke(null, Integer.MAX_VALUE));
    }
}
