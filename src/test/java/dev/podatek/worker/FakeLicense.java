package dev.podatek.worker;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** A stand-in relocated PodatekLicense with init(Plugin) and shutdown() so refs resolve in tests. */
final class FakeLicense {
    private FakeLicense() {}
    static byte[] bytes(String internalName) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                internalName, null, "java/lang/Object", null);
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "init",
                "(Lorg/bukkit/plugin/Plugin;)V", null, null);
        init.visitCode(); init.visitInsn(Opcodes.RETURN); init.visitMaxs(0, 0); init.visitEnd();
        MethodVisitor sd = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "shutdown",
                "()V", null, null);
        sd.visitCode(); sd.visitInsn(Opcodes.RETURN); sd.visitMaxs(0, 0); sd.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }
}
