package dev.podatek.worker;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ObfuscatorLayer2Test {

    private static final String PFX = "p1234";
    private static final byte[] SALT = {0x11, 0x42, (byte) 0x9c, 0x07, 0x5b, (byte) 0xa3, 0x2f, 0x60};

    private static int branchCount(byte[] cls, String method) {
        ClassNode cn = new ClassNode();
        new ClassReader(cls).accept(cn, 0);
        int n = 0;
        for (MethodNode mn : cn.methods) {
            if (!mn.name.equals(method)) continue;
            for (AbstractInsnNode in = mn.instructions.getFirst(); in != null; in = in.getNext())
                if (in instanceof JumpInsnNode) n++;
        }
        return n;
    }

    /** class with a branch-free method add(int,int) and a string method msg(). */
    private static byte[] sample(String internal) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                internal, null, "java/lang/Object", null);
        MethodVisitor add = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "add", "(II)I", null, null);
        add.visitCode();
        add.visitVarInsn(Opcodes.ILOAD, 0);
        add.visitVarInsn(Opcodes.ILOAD, 1);
        add.visitInsn(Opcodes.IADD);
        add.visitInsn(Opcodes.IRETURN);
        add.visitMaxs(0, 0);
        add.visitEnd();
        MethodVisitor msg = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "msg", "()Ljava/lang/String;", null, null);
        msg.visitCode();
        msg.visitLdcInsn("https://license.podatek.dev/secret");
        msg.visitInsn(Opcodes.ARETURN);
        msg.visitMaxs(0, 0);
        msg.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    @Test void injectsOpaqueBranchesButPreservesSemantics() throws Exception {
        byte[] before = sample(PFX + "/S");
        assertEquals(0, branchCount(before, "add"), "sample add() should start branch-free");

        Map<String, byte[]> in = new LinkedHashMap<>();
        in.put(PFX + "/S.class", before);
        Map<String, byte[]> obf = Obfuscator.obfuscate(in, PFX, SALT);

        // opaque predicate injected -> add() now has >=1 branch
        assertTrue(branchCount(obf.get(PFX + "/S.class"), "add") >= 1,
                "expected an opaque branch injected into add()");

        // decoder+opaque holder present
        assertNotNull(obf.get(PFX + "/K.class"), "holder K must be emitted");

        // semantics unchanged: add still adds, msg still decodes to the original
        TestClassLoaders.ByteArrayClassLoader cl = TestClassLoaders.loader(obf);
        Class<?> s = Class.forName(PFX + ".S", true, cl);
        assertEquals(5, s.getMethod("add", int.class, int.class).invoke(null, 2, 3));
        assertEquals(-7, s.getMethod("add", int.class, int.class).invoke(null, 3, -10));
        assertEquals("https://license.podatek.dev/secret", s.getMethod("msg").invoke(null));
    }
}
