package dev.podatek.worker;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;

/**
 * Obfuscates ONLY our injected classes (keys under {@code relocPrefix/}), never the host.
 *
 * <p>Layer 1 — string encryption: every {@code String} constant loaded in a method body of one
 * of our logic classes is replaced by a baked, XOR-encrypted {@code byte[]} plus a call to a
 * synthesized decoder {@code <relocPrefix>/K.d([B)}. FernFlower/Vineflower then sees an opaque
 * byte array and a decode call instead of the plaintext URL / endpoint / message.
 *
 * <p>Scope excludes the shaded crypto library ({@code relocPrefix/shaded/**} — public code, not
 * our IP) and {@code GeneratedConfig} (its constants are already XOR-encrypted by
 * {@link ConfigEmitter}). The decoder holder {@code K} is itself a fresh class with only
 * {@code java/*} references, so its frames compute safely.
 */
public final class Obfuscator {

    private Obfuscator() {}

    static final String DECODER_NAME = "d";
    static final String DECODER_DESC = "([B)Ljava/lang/String;";

    public static Map<String, byte[]> obfuscate(Map<String, byte[]> classes, String relocPrefix, byte[] salt) {
        if (salt == null || salt.length == 0) return classes;
        String holderInternal = relocPrefix + "/K";

        Map<String, byte[]> out = new LinkedHashMap<>();
        boolean anyEncrypted = false;
        for (Map.Entry<String, byte[]> e : classes.entrySet()) {
            String key = e.getKey();
            if (isTarget(key, relocPrefix)) {
                byte[] rewritten = encryptStrings(e.getValue(), holderInternal, salt);
                out.put(key, rewritten);
                anyEncrypted = true;
            } else {
                out.put(key, e.getValue());
            }
        }
        // Emit the shared decoder holder only if at least one class was processed.
        if (anyEncrypted) {
            out.put(holderInternal + ".class", emitDecoderHolder(holderInternal, salt));
        }
        return out;
    }

    /** Our logic classes: under the prefix, a class, but not the shaded lib nor GeneratedConfig. */
    static boolean isTarget(String key, String relocPrefix) {
        if (!key.startsWith(relocPrefix + "/")) return false;
        if (!key.endsWith(".class")) return false;
        if (key.startsWith(relocPrefix + "/shaded/")) return false;
        if (key.equals(relocPrefix + "/GeneratedConfig.class")) return false;
        return true;
    }

    /** Replaces every String-constant LDC in method bodies with byte[] + decoder call. */
    private static byte[] encryptStrings(byte[] classBytes, String holderInternal, byte[] salt) {
        ClassNode cn = new ClassNode();
        // flags 0: keep existing stack-map frames untouched (we don't add branches).
        new ClassReader(classBytes).accept(cn, 0);

        // (a) method-body String LDCs -> byte[] + decoder call.
        if (cn.methods != null) {
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                ListIterator<AbstractInsnNode> it = mn.instructions.iterator();
                while (it.hasNext()) {
                    AbstractInsnNode insn = it.next();
                    if (!(insn instanceof LdcInsnNode)) continue;
                    Object cst = ((LdcInsnNode) insn).cst;
                    if (!(cst instanceof String)) continue;
                    InsnList repl = decodeSequence((String) cst, holderInternal, salt);
                    mn.instructions.insertBefore(insn, repl);
                    it.remove(); // drop the original LDC
                }
            }
        }

        // (b) static-final String ConstantValue fields leak the literal in the constant pool even
        // when every use site is inlined. Strip the ConstantValue and initialize the field in
        // <clinit> from an encrypted byte[], so the plaintext is gone but reads still work.
        List<FieldNode> constStringFields = new ArrayList<>();
        if (cn.fields != null) {
            for (FieldNode fn : cn.fields) {
                if (fn.value instanceof String && (fn.access & Opcodes.ACC_STATIC) != 0) {
                    constStringFields.add(fn);
                }
            }
        }
        if (!constStringFields.isEmpty()) {
            MethodNode clinit = findOrCreateClinit(cn);
            InsnList init = new InsnList();
            for (FieldNode fn : constStringFields) {
                init.add(decodeSequence((String) fn.value, holderInternal, salt));
                init.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, fn.name, fn.desc));
                fn.value = null; // drop the ConstantValue attribute
            }
            clinit.instructions.insert(init); // prepend, before any other static init
        }

        // COMPUTE_MAXS: recompute max stack for the deeper byte[]-build; NO frame recompute
        // (so getCommonSuperClass is never called on absent bukkit types).
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        return cw.toByteArray();
    }

    /** Returns the existing {@code <clinit>}, or creates an empty one (RETURN) and adds it. */
    private static MethodNode findOrCreateClinit(ClassNode cn) {
        if (cn.methods != null) {
            for (MethodNode mn : cn.methods) {
                if ("<clinit>".equals(mn.name) && "()V".equals(mn.desc)) return mn;
            }
        }
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        cn.methods.add(clinit);
        return clinit;
    }

    /** Builds: push encrypted byte[]; INVOKESTATIC holder.d([B)String. Net stack effect: +1 String. */
    private static InsnList decodeSequence(String value, String holderInternal, byte[] salt) {
        byte[] enc = xor(value.getBytes(StandardCharsets.UTF_8), salt);
        InsnList l = new InsnList();
        pushInt(l, enc.length);
        l.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        for (int i = 0; i < enc.length; i++) {
            l.add(new InsnNode(Opcodes.DUP));
            pushInt(l, i);
            pushInt(l, enc[i]);
            l.add(new InsnNode(Opcodes.BASTORE));
        }
        l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, holderInternal, DECODER_NAME, DECODER_DESC, false));
        return l;
    }

    private static void pushInt(InsnList l, int v) {
        if (v >= -1 && v <= 5) l.add(new InsnNode(Opcodes.ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) l.add(new IntInsnNode(Opcodes.BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) l.add(new IntInsnNode(Opcodes.SIPUSH, v));
        else l.add(new LdcInsnNode(v));
    }

    /**
     * Fresh holder class {@code <holder>} with {@code public static String d(byte[])} that XOR-decodes
     * with the baked salt. Only java/* references, so COMPUTE_FRAMES computes safely.
     */
    private static byte[] emitDecoderHolder(String holderInternal, byte[] salt) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                holderInternal, null, "java/lang/Object", null);

        MethodVisitor ctor = cw.visitMethod(Opcodes.ACC_PRIVATE, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        ctor.visitInsn(Opcodes.RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                DECODER_NAME, DECODER_DESC, null, null);
        mv.visitCode();
        // byte[] s = new byte[]{salt...}  -> local 1
        emitByteArrayLiteral(mv, salt);
        mv.visitVarInsn(Opcodes.ASTORE, 1);
        // for (int i=0;i<enc.length;i++) enc[i] ^= s[i % s.length];  i -> local 2
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ISTORE, 2);
        org.objectweb.asm.Label top = new org.objectweb.asm.Label();
        org.objectweb.asm.Label end = new org.objectweb.asm.Label();
        mv.visitLabel(top);
        mv.visitVarInsn(Opcodes.ILOAD, 2);
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitInsn(Opcodes.ARRAYLENGTH);
        mv.visitJumpInsn(Opcodes.IF_ICMPGE, end);
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 2);
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitVarInsn(Opcodes.ILOAD, 2);
        mv.visitInsn(Opcodes.BALOAD);
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitVarInsn(Opcodes.ILOAD, 2);
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitInsn(Opcodes.ARRAYLENGTH);
        mv.visitInsn(Opcodes.IREM);
        mv.visitInsn(Opcodes.BALOAD);
        mv.visitInsn(Opcodes.IXOR);
        mv.visitInsn(Opcodes.I2B);
        mv.visitInsn(Opcodes.BASTORE);
        mv.visitIincInsn(2, 1);
        mv.visitJumpInsn(Opcodes.GOTO, top);
        mv.visitLabel(end);
        // return new String(enc, UTF_8)
        mv.visitTypeInsn(Opcodes.NEW, "java/lang/String");
        mv.visitInsn(Opcodes.DUP);
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitFieldInsn(Opcodes.GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8",
                "Ljava/nio/charset/Charset;");
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>",
                "([BLjava/nio/charset/Charset;)V", false);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void emitByteArrayLiteral(MethodVisitor mv, byte[] data) {
        pushIntMv(mv, data.length);
        mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
        for (int i = 0; i < data.length; i++) {
            mv.visitInsn(Opcodes.DUP);
            pushIntMv(mv, i);
            pushIntMv(mv, data[i]);
            mv.visitInsn(Opcodes.BASTORE);
        }
    }

    private static void pushIntMv(MethodVisitor mv, int v) {
        if (v >= -1 && v <= 5) mv.visitInsn(Opcodes.ICONST_0 + v);
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) mv.visitIntInsn(Opcodes.BIPUSH, v);
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) mv.visitIntInsn(Opcodes.SIPUSH, v);
        else mv.visitLdcInsn(v);
    }

    private static byte[] xor(byte[] data, byte[] salt) {
        byte[] o = new byte[data.length];
        for (int i = 0; i < data.length; i++) o[i] = (byte) (data[i] ^ salt[i % salt.length]);
        return o;
    }
}
