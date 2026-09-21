package dev.podatek.worker;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Builds a standalone guard plugin around the baked license client. */
final class PackGuardEmitter {
    private static final SecureRandom RNG = new SecureRandom();

    private PackGuardEmitter() {}

    static byte[] build(InjectConfig cfg, List<String> managedPluginNames) {
        String prefix = "g" + randomHex(12);
        byte[] salt = new byte[16];
        RNG.nextBytes(salt);

        Map<String, byte[]> out = new LinkedHashMap<>(Relocator.relocate(ClientPayload.classes(), prefix));
        out.put(prefix + "/GeneratedConfig.class", ConfigEmitter.emit(prefix, cfg, salt));
        out.put(prefix + "/PackGuardPlugin.class", emitMain(prefix, managedPluginNames));
        String yml = "name: PodatekPackGuard\n"
                + "version: 1.0.0\n"
                + "main: " + prefix + ".PackGuardPlugin\n"
                + "api-version: '1.16'\n"
                + "load: STARTUP\n"
                + "description: License guard generated for a protected plugin package.\n";
        out.put("plugin.yml", yml.getBytes(StandardCharsets.UTF_8));
        out = Obfuscator.obfuscate(out, prefix, salt);
        return PackageProtector.writeZip(out);
    }

    private static byte[] emitMain(String prefix, List<String> names) {
        String owner = prefix + "/PackGuardPlugin";
        String license = prefix + "/PodatekLicense";
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                owner, null, "org/bukkit/plugin/java/JavaPlugin", new String[]{"java/lang/Runnable"});

        MethodVisitor ctor = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(Opcodes.INVOKESPECIAL, "org/bukkit/plugin/java/JavaPlugin", "<init>", "()V", false);
        ctor.visitInsn(Opcodes.RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        MethodVisitor enable = cw.visitMethod(Opcodes.ACC_PUBLIC, "onEnable", "()V", null, null);
        enable.visitCode();
        enable.visitVarInsn(Opcodes.ALOAD, 0);
        enable.visitMethodInsn(Opcodes.INVOKESTATIC, license, "init", "(Lorg/bukkit/plugin/Plugin;)V", false);
        enable.visitInsn(Opcodes.ACONST_NULL);
        enable.visitVarInsn(Opcodes.ALOAD, 0);
        enable.visitMethodInsn(Opcodes.INVOKESTATIC, license, "wireFeature", "(Ljava/lang/Runnable;Ljava/lang/Runnable;)V", false);
        enable.visitMethodInsn(Opcodes.INVOKESTATIC, license, "isFeatureEnabled", "()Z", false);
        Label licensed = new Label();
        enable.visitJumpInsn(Opcodes.IFNE, licensed);
        enable.visitVarInsn(Opcodes.ALOAD, 0);
        enable.visitMethodInsn(Opcodes.INVOKEVIRTUAL, owner, "run", "()V", false);
        enable.visitLabel(licensed);
        enable.visitInsn(Opcodes.RETURN);
        enable.visitMaxs(0, 0);
        enable.visitEnd();

        MethodVisitor disable = cw.visitMethod(Opcodes.ACC_PUBLIC, "onDisable", "()V", null, null);
        disable.visitCode();
        disable.visitMethodInsn(Opcodes.INVOKESTATIC, license, "shutdown", "()V", false);
        disable.visitInsn(Opcodes.RETURN);
        disable.visitMaxs(0, 0);
        disable.visitEnd();

        MethodVisitor run = cw.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
        run.visitCode();
        for (String name : names) {
            Label next = new Label();
            run.visitMethodInsn(Opcodes.INVOKESTATIC, "org/bukkit/Bukkit", "getPluginManager", "()Lorg/bukkit/plugin/PluginManager;", false);
            run.visitLdcInsn(name);
            run.visitMethodInsn(Opcodes.INVOKEINTERFACE, "org/bukkit/plugin/PluginManager", "getPlugin", "(Ljava/lang/String;)Lorg/bukkit/plugin/Plugin;", true);
            run.visitVarInsn(Opcodes.ASTORE, 1);
            run.visitVarInsn(Opcodes.ALOAD, 1);
            run.visitJumpInsn(Opcodes.IFNULL, next);
            run.visitVarInsn(Opcodes.ALOAD, 1);
            run.visitMethodInsn(Opcodes.INVOKEINTERFACE, "org/bukkit/plugin/Plugin", "isEnabled", "()Z", true);
            run.visitJumpInsn(Opcodes.IFEQ, next);
            run.visitMethodInsn(Opcodes.INVOKESTATIC, "org/bukkit/Bukkit", "getPluginManager", "()Lorg/bukkit/plugin/PluginManager;", false);
            run.visitVarInsn(Opcodes.ALOAD, 1);
            run.visitMethodInsn(Opcodes.INVOKEINTERFACE, "org/bukkit/plugin/PluginManager", "disablePlugin", "(Lorg/bukkit/plugin/Plugin;)V", true);
            run.visitLabel(next);
        }
        run.visitInsn(Opcodes.RETURN);
        run.visitMaxs(0, 0);
        run.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    private static String randomHex(int chars) {
        byte[] bytes = new byte[(chars + 1) / 2];
        RNG.nextBytes(bytes);
        StringBuilder out = new StringBuilder();
        for (byte value : bytes) out.append(String.format("%02x", value & 0xff));
        return out.substring(0, chars);
    }
}
