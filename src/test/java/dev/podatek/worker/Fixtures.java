package dev.podatek.worker;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Builds tiny in-memory plugin jars for tests. Main class bytecode is synthesized with ASM. */
final class Fixtures {
    private Fixtures() {}

    static final String DEMO_YML =
            "name: Demo\nversion: 1.0.0\nmain: com.demo.DemoPlugin\napi-version: 1.16\n";

    /** A jar with plugin.yml + a compiled `main` class extending JavaPlugin (empty onEnable). */
    static byte[] pluginJar(String main, String yml) {
        String internal = main.replace('.', '/');
        byte[] cls = pluginClass(internal, false, false);
        return jar(internal, cls, yml);
    }

    /** A jar whose main class is `final` and has NO onEnable override (forces asm-insert fallback). */
    static byte[] finalMainPluginJar() {
        String internal = "com/demo/DemoPlugin";
        byte[] cls = pluginClass(internal, true, true);
        String yml = "name: Demo\nversion: 1.0.0\nmain: com.demo.DemoPlugin\n";
        return jar(internal, cls, yml);
    }

    static byte[] jar(String internalMain, byte[] mainClass, String yml) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (ZipOutputStream zos = new ZipOutputStream(bos)) {
                zos.putNextEntry(new ZipEntry("plugin.yml"));
                zos.write(yml.getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
                zos.putNextEntry(new ZipEntry(internalMain + ".class"));
                zos.write(mainClass);
                zos.closeEntry();
            }
            return bos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generates a JavaPlugin subclass.
     * @param makeFinal   emit ACC_FINAL on the class
     * @param noOnEnable  if true, omit the onEnable override entirely
     */
    static byte[] pluginClass(String internalName, boolean makeFinal, boolean noOnEnable) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
        int access = Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER | (makeFinal ? Opcodes.ACC_FINAL : 0);
        cw.visit(Opcodes.V1_8, access, internalName, null,
                "org/bukkit/plugin/java/JavaPlugin", null);

        MethodVisitor ctor = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(Opcodes.INVOKESPECIAL, "org/bukkit/plugin/java/JavaPlugin",
                "<init>", "()V", false);
        ctor.visitInsn(Opcodes.RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        if (!noOnEnable) {
            MethodVisitor oe = cw.visitMethod(Opcodes.ACC_PUBLIC, "onEnable", "()V", null, null);
            oe.visitCode();
            oe.visitInsn(Opcodes.RETURN);
            oe.visitMaxs(0, 0);
            oe.visitEnd();
        }

        cw.visitEnd();
        return cw.toByteArray();
    }
}
