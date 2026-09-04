package dev.podatek.worker;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
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
 * <p><b>Layer 1 — string encryption.</b> Every {@code String} constant in a method body of one of
 * our logic classes is replaced by a baked, XOR-encrypted {@code byte[]} plus a call to a
 * synthesized decoder {@code <relocPrefix>/K.d([B)}. {@code static final String} ConstantValue
 * fields are stripped and re-initialized in {@code <clinit>} from an encrypted {@code byte[]}, so
 * no plaintext remains in the constant pool either. A decompiler then sees an opaque byte array
 * and a decode call instead of the plaintext URL / endpoint / message.
 *
 * <p><b>Layer 2 — opaque predicates + junk.</b> Each eligible method is prefixed with an
 * always-true predicate ({@code (K.Q | 1) != 0}, where {@code K.Q} is seeded at runtime so the
 * decompiler cannot fold it) guarding a dead junk block. The reader must analyze a branch and a
 * bogus block that never executes.
 *
 * <p>Scope excludes the shaded crypto library ({@code relocPrefix/shaded/**} — public code, not
 * our IP) and {@code GeneratedConfig} (already XOR-encrypted by {@link ConfigEmitter}).
 *
 * <p><b>Frame strategy.</b> Classes are read with {@code EXPAND_FRAMES} (all frames absolute), so a
 * single manually-built frame can be inserted at the opaque branch target without breaking the
 * relative frame chain, and written back with {@code COMPUTE_MAXS}. Frames are never recomputed, so
 * {@code getCommonSuperClass} is never called on the {@code org/bukkit/**} types that are absent
 * from the worker runtime. The holder {@code K} is a fresh {@code java/*}-only class.
 */
public final class Obfuscator {

    private Obfuscator() {}

    static final String DECODER_NAME = "d";
    static final String DECODER_DESC = "([B)Ljava/lang/String;";
    static final String OPAQUE_FIELD = "Q";
    static final String OPAQUE_DESC = "I";
    private static final byte[] JUNK_DECOY = {0x4f, 0x4b, 0x2d, 0x67, 0x72, 0x61, 0x63, 0x65}; // "OK-grace"

    public static Map<String, byte[]> obfuscate(Map<String, byte[]> classes, String relocPrefix, byte[] salt) {
        if (salt == null || salt.length == 0) return classes;
        String holderInternal = relocPrefix + "/K";

        Map<String, byte[]> out = new LinkedHashMap<>();
        boolean anyProcessed = false;
        for (Map.Entry<String, byte[]> e : classes.entrySet()) {
            String key = e.getKey();
            if (isTarget(key, relocPrefix)) {
                out.put(key, transform(e.getValue(), holderInternal, salt));
                anyProcessed = true;
            } else {
                out.put(key, e.getValue());
            }
        }
        // The holder backs both the decoder (Layer 1) and the opaque seed (Layer 2), so it must
        // exist whenever any class was processed — not only when strings were encrypted.
        if (anyProcessed) {
            out.put(holderInternal + ".class", emitHolder(holderInternal, salt));
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

    /**
     * Applies all layers, then guarantees the result is well-formed by re-reading it with ASM. If
     * control-flow layers produced a class ASM cannot round-trip (a rare frame edge case that the
     * JVM may still accept — we do not ship it), the class is degraded to string-encryption only,
     * which is proven safe and always round-trips. No plaintext leaks in either case.
     */
    private static byte[] transform(byte[] classBytes, String holderInternal, byte[] salt) {
        byte[] full = apply(classBytes, holderInternal, salt, true);
        if (roundTrips(full)) return full;
        return apply(classBytes, holderInternal, salt, false);
    }

    private static byte[] apply(byte[] classBytes, String holderInternal, byte[] salt, boolean controlFlow) {
        ClassNode cn = new ClassNode();
        // EXPAND_FRAMES: frames become absolute (F_NEW), so we may insert one freely.
        new ClassReader(classBytes).accept(cn, ClassReader.EXPAND_FRAMES);

        if (cn.methods != null) {
            for (MethodNode mn : cn.methods) {
                boolean flattened = controlFlow && Flattener.flatten(mn, cn.name);   // Layer 3
                encryptMethodStrings(mn, holderInternal, salt);                      // Layer 1
                if (controlFlow && !flattened) {
                    injectOpaquePredicate(mn, cn.name, holderInternal, salt);        // Layer 2
                }
            }
        }
        encryptConstantValueFields(cn, holderInternal, salt);     // Layer 1 (fields)

        // COMPUTE_MAXS only: recompute max stack/locals; frames are written from the (absolute)
        // FrameNodes as-is, so no reference-type merging and no class loading occurs.
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cn.accept(cw);
        return cw.toByteArray();
    }

    /** True iff ASM can fully re-read the class (frames included). */
    private static boolean roundTrips(byte[] classBytes) {
        try {
            new ClassReader(classBytes).accept(new ClassNode(), 0);
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    // ---- Layer 1: strings -----------------------------------------------------------------

    private static void encryptMethodStrings(MethodNode mn, String holderInternal, byte[] salt) {
        if (mn.instructions == null || mn.instructions.size() == 0) return;
        ListIterator<AbstractInsnNode> it = mn.instructions.iterator();
        while (it.hasNext()) {
            AbstractInsnNode insn = it.next();
            if (!(insn instanceof LdcInsnNode)) continue;
            Object cst = ((LdcInsnNode) insn).cst;
            if (!(cst instanceof String)) continue;
            mn.instructions.insertBefore(insn, decodeSequence((String) cst, holderInternal, salt));
            it.remove();
        }
    }

    private static void encryptConstantValueFields(ClassNode cn, String holderInternal, byte[] salt) {
        List<FieldNode> constStringFields = new ArrayList<>();
        if (cn.fields != null) {
            for (FieldNode fn : cn.fields) {
                if (fn.value instanceof String && (fn.access & Opcodes.ACC_STATIC) != 0) {
                    constStringFields.add(fn);
                }
            }
        }
        if (constStringFields.isEmpty()) return;
        MethodNode clinit = findOrCreateClinit(cn);
        InsnList init = new InsnList();
        for (FieldNode fn : constStringFields) {
            init.add(decodeSequence((String) fn.value, holderInternal, salt));
            init.add(new FieldInsnNode(Opcodes.PUTSTATIC, cn.name, fn.name, fn.desc));
            fn.value = null; // drop the ConstantValue attribute
        }
        clinit.instructions.insert(init); // prepend, before any other static init
    }

    // ---- Layer 2: opaque predicate + junk -------------------------------------------------

    /**
     * Prepends {@code if ((K.Q | 1) != 0) goto real; <junk>; real:} to eligible methods. The
     * predicate is always true (any int OR 1 is nonzero); {@code K.Q} is seeded at runtime so a
     * decompiler cannot fold it. Skips constructors, static initializers, and abstract/native/empty
     * methods (injecting before a super() call, or into a bodyless method, is illegal).
     */
    private static void injectOpaquePredicate(MethodNode mn, String owner, String holderInternal, byte[] salt) {
        if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name)) return;
        if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) return;
        if (mn.instructions == null || mn.instructions.size() == 0) return;

        LabelNode real = new LabelNode();
        InsnList pre = new InsnList();
        // (K.Q | 1) != 0  ->  branch to real (always taken)
        pre.add(new FieldInsnNode(Opcodes.GETSTATIC, holderInternal, OPAQUE_FIELD, OPAQUE_DESC));
        pre.add(new InsnNode(Opcodes.ICONST_1));
        pre.add(new InsnNode(Opcodes.IOR));
        pre.add(new JumpInsnNode(Opcodes.IFNE, real));
        // dead junk (never runs): decode a decoy string and discard. Stack-neutral (empty -> empty).
        pre.add(pushByteArrayList(xor(JUNK_DECOY, salt)));
        pre.add(new MethodInsnNode(Opcodes.INVOKESTATIC, holderInternal, DECODER_NAME, DECODER_DESC, false));
        pre.add(new InsnNode(Opcodes.POP));
        // real: (branch target) — explicit absolute frame = method entry (params, empty stack)
        pre.add(real);
        Object[] locals = entryLocals(mn.access, owner, mn.desc);
        pre.add(new FrameNode(Opcodes.F_NEW, locals.length, locals, 0, new Object[0]));

        mn.instructions.insert(pre); // prepend to the whole method
    }

    /** Frame locals at method entry: {@code this} (if instance) followed by the argument types. */
    private static Object[] entryLocals(int access, String owner, String desc) {
        List<Object> l = new ArrayList<>();
        if ((access & Opcodes.ACC_STATIC) == 0) l.add(owner);
        for (Type t : Type.getArgumentTypes(desc)) {
            switch (t.getSort()) {
                case Type.BOOLEAN: case Type.CHAR: case Type.BYTE:
                case Type.SHORT: case Type.INT: l.add(Opcodes.INTEGER); break;
                case Type.FLOAT: l.add(Opcodes.FLOAT); break;
                case Type.LONG: l.add(Opcodes.LONG); break;
                case Type.DOUBLE: l.add(Opcodes.DOUBLE); break;
                case Type.ARRAY: l.add(t.getDescriptor()); break;
                default: l.add(t.getInternalName());
            }
        }
        return l.toArray();
    }

    // ---- shared helpers -------------------------------------------------------------------

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
        InsnList l = pushByteArrayList(xor(value.getBytes(StandardCharsets.UTF_8), salt));
        l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, holderInternal, DECODER_NAME, DECODER_DESC, false));
        return l;
    }

    private static InsnList pushByteArrayList(byte[] enc) {
        InsnList l = new InsnList();
        pushInt(l, enc.length);
        l.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        for (int i = 0; i < enc.length; i++) {
            l.add(new InsnNode(Opcodes.DUP));
            pushInt(l, i);
            pushInt(l, enc[i]);
            l.add(new InsnNode(Opcodes.BASTORE));
        }
        return l;
    }

    private static void pushInt(InsnList l, int v) {
        if (v >= -1 && v <= 5) l.add(new InsnNode(Opcodes.ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) l.add(new IntInsnNode(Opcodes.BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) l.add(new IntInsnNode(Opcodes.SIPUSH, v));
        else l.add(new LdcInsnNode(v));
    }

    /**
     * Fresh holder {@code K}: {@code static String d(byte[])} (XOR decoder with baked salt) and
     * {@code static int Q} seeded at runtime. Only {@code java/*} references, so COMPUTE_FRAMES is safe.
     */
    private static byte[] emitHolder(String holderInternal, byte[] salt) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                holderInternal, null, "java/lang/Object", null);

        cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, OPAQUE_FIELD, OPAQUE_DESC, null, null).visitEnd();

        MethodVisitor ctor = cw.visitMethod(Opcodes.ACC_PRIVATE, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        ctor.visitInsn(Opcodes.RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        // static { Q = (int) System.nanoTime(); }  -- runtime seed => decompiler cannot fold (Q|1)!=0
        MethodVisitor cl = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        cl.visitCode();
        cl.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "nanoTime", "()J", false);
        cl.visitInsn(Opcodes.L2I);
        cl.visitFieldInsn(Opcodes.PUTSTATIC, holderInternal, OPAQUE_FIELD, OPAQUE_DESC);
        cl.visitInsn(Opcodes.RETURN);
        cl.visitMaxs(0, 0);
        cl.visitEnd();

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                DECODER_NAME, DECODER_DESC, null, null);
        mv.visitCode();
        emitByteArrayLiteral(mv, salt);          // byte[] s = {salt...} -> local 1
        mv.visitVarInsn(Opcodes.ASTORE, 1);
        mv.visitInsn(Opcodes.ICONST_0);          // i = 0 -> local 2
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
