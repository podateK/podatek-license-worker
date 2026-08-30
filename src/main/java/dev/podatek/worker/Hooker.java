package dev.podatek.worker;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Hooks the host plugin's lifecycle to drive the license client.
 * PRIMARY: synthesize {@code <prefix>/LicenseShim extends <hostMain>} and repoint plugin.yml.
 * FALLBACK: ASM in-place insert into the host main (when it is {@code final} / no usable ctor).
 */
public final class Hooker {

    private static final String PLUGIN = "org/bukkit/plugin/Plugin";

    private Hooker() {}

    public static final class HookResult {
        public final String mode;
        public final String newMainClass;
        private final Map<String, byte[]> addedOrPatched;
        HookResult(String mode, Map<String, byte[]> addedOrPatched, String newMainClass) {
            this.mode = mode;
            this.addedOrPatched = addedOrPatched;
            this.newMainClass = newMainClass;
        }
        public Map<String, byte[]> addedOrPatched() { return addedOrPatched; }
    }

    public static HookResult hook(JarModel host, String prefix) {
        String mainDotted = host.descriptor().mainClass;
        if (mainDotted == null || mainDotted.isEmpty()) {
            throw new InjectException(400, "brak 'main' w plugin.yml");
        }
        String hostInternal = mainDotted.replace('.', '/');
        byte[] hostBytes = host.entries().get(hostInternal + ".class");
        if (hostBytes == null) {
            throw new InjectException(422, "klasa main nie znaleziona w jar: " + mainDotted);
        }

        MainInfo info = inspect(hostBytes);
        String licenseInternal = prefix + "/PodatekLicense";

        if (!info.isFinal && info.hasAccessibleNoArgCtor) {
            byte[] shim = synthesizeShim(prefix, hostInternal, licenseInternal);
            Map<String, byte[]> out = new LinkedHashMap<>();
            out.put(prefix + "/LicenseShim.class", shim);
            return new HookResult("shim", out, dotted(prefix + "/LicenseShim"));
        }

        // FALLBACK: in-place insert into the host main.
        byte[] patched = insertInPlace(hostBytes, licenseInternal);
        Map<String, byte[]> out = new LinkedHashMap<>();
        out.put(hostInternal + ".class", patched);
        return new HookResult("asm-insert", out, mainDotted);
    }

    private static String dotted(String internal) { return internal.replace('/', '.'); }

    // ---- host inspection -------------------------------------------------

    private static final class MainInfo {
        boolean isFinal;
        boolean hasAccessibleNoArgCtor;
        boolean hasOnEnable;
        boolean hasOnDisable;
        String superName;
    }

    private static MainInfo inspect(byte[] bytes) {
        MainInfo info = new MainInfo();
        ClassReader cr = new ClassReader(bytes);
        cr.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override public void visit(int version, int access, String name, String sig,
                                        String superName, String[] interfaces) {
                info.isFinal = (access & Opcodes.ACC_FINAL) != 0;
                info.superName = superName;
            }
            @Override public MethodVisitor visitMethod(int access, String name, String desc,
                                                       String sig, String[] exceptions) {
                if (name.equals("<init>") && desc.equals("()V")
                        && (access & Opcodes.ACC_PRIVATE) == 0) {
                    info.hasAccessibleNoArgCtor = true;
                }
                if (name.equals("onEnable") && desc.equals("()V")) info.hasOnEnable = true;
                if (name.equals("onDisable") && desc.equals("()V")) info.hasOnDisable = true;
                return null;
            }
        }, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        return info;
    }

    // ---- PRIMARY: shim ---------------------------------------------------

    private static byte[] synthesizeShim(String prefix, String hostInternal, String licenseInternal) {
        String shimInternal = prefix + "/LicenseShim";
        // COMPUTE_MAXS only: host/bukkit types are not on the worker runtime classpath, so we must
        // never trigger COMPUTE_FRAMES (which would try to resolve the class hierarchy).
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                shimInternal, null, hostInternal, null);

        // default ctor -> super()
        MethodVisitor ctor = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(Opcodes.INVOKESPECIAL, hostInternal, "<init>", "()V", false);
        ctor.visitInsn(Opcodes.RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        // onEnable() { PodatekLicense.init(this); super.onEnable(); }
        MethodVisitor oe = cw.visitMethod(Opcodes.ACC_PUBLIC, "onEnable", "()V", null, null);
        oe.visitCode();
        oe.visitVarInsn(Opcodes.ALOAD, 0);
        oe.visitMethodInsn(Opcodes.INVOKESTATIC, licenseInternal, "init",
                "(L" + PLUGIN + ";)V", false);
        oe.visitVarInsn(Opcodes.ALOAD, 0);
        oe.visitMethodInsn(Opcodes.INVOKESPECIAL, hostInternal, "onEnable", "()V", false);
        oe.visitInsn(Opcodes.RETURN);
        oe.visitMaxs(0, 0);
        oe.visitEnd();

        // onDisable() { super.onDisable(); PodatekLicense.shutdown(); }
        MethodVisitor od = cw.visitMethod(Opcodes.ACC_PUBLIC, "onDisable", "()V", null, null);
        od.visitCode();
        od.visitVarInsn(Opcodes.ALOAD, 0);
        od.visitMethodInsn(Opcodes.INVOKESPECIAL, hostInternal, "onDisable", "()V", false);
        od.visitMethodInsn(Opcodes.INVOKESTATIC, licenseInternal, "shutdown", "()V", false);
        od.visitInsn(Opcodes.RETURN);
        od.visitMaxs(0, 0);
        od.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    // ---- FALLBACK: in-place insert --------------------------------------

    private static byte[] insertInPlace(byte[] hostBytes, String licenseInternal) {
        ClassNode cn = new ClassNode();
        new ClassReader(hostBytes).accept(cn, 0);

        MethodNode onEnable = find(cn, "onEnable");
        if (onEnable == null) {
            onEnable = synthLifecycle(cn.superName, "onEnable");
            cn.methods.add(onEnable);
        }
        // Prepend: PodatekLicense.init(this);  (stack-neutral, existing frames stay valid)
        InsnList initCall = new InsnList();
        initCall.add(new VarInsnNode(Opcodes.ALOAD, 0));
        initCall.add(new MethodInsnNode(Opcodes.INVOKESTATIC, licenseInternal, "init",
                "(L" + PLUGIN + ";)V", false));
        onEnable.instructions.insert(initCall);

        MethodNode onDisable = find(cn, "onDisable");
        if (onDisable == null) {
            onDisable = synthLifecycle(cn.superName, "onDisable");
            cn.methods.add(onDisable);
        }
        InsnList shutdownCall = new InsnList();
        shutdownCall.add(new MethodInsnNode(Opcodes.INVOKESTATIC, licenseInternal, "shutdown",
                "()V", false));
        onDisable.instructions.insert(shutdownCall);

        // COMPUTE_MAXS keeps existing stack-map frames; our inserts are stack-neutral.
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        return cw.toByteArray();
    }

    private static MethodNode find(ClassNode cn, String name) {
        for (MethodNode m : cn.methods) {
            if (m.name.equals(name) && m.desc.equals("()V")) return m;
        }
        return null;
    }

    /** Synthesize {@code void name() { super.name(); }} (init/shutdown inserted by caller). */
    private static MethodNode synthLifecycle(String superName, String name) {
        MethodNode m = new MethodNode(Opcodes.ACC_PUBLIC, name, "()V", null, null);
        m.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        m.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, superName, name, "()V", false));
        m.instructions.add(new InsnNode(Opcodes.RETURN));
        return m;
    }
}
