package dev.podatek.worker;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.Map;

/**
 * Emits a relocated {@code <prefix>/GeneratedConfig} whose {@code load()} returns the injected
 * request values. Replaces the client's dev-placeholder config. Bytecode major 52 (V1_8).
 */
public final class ConfigEmitter {

    private ConfigEmitter() {}

    /**
     * @param prefix relocation prefix (internal-name segment, e.g. {@code "p9"})
     * @param cfg    the license config to bake in
     * @param salt   XOR salt for string obfuscation (non-empty enables obfuscation)
     */
    public static byte[] emit(String prefix, InjectConfig cfg, byte[] salt) {
        String owner = prefix + "/GeneratedConfig";
        // Stage 1 (de-risking): plain LDC constants only. XOR obfuscation enabled in a later commit.
        boolean obfuscate = false;

        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                owner, null, "java/lang/Object", null);

        // public final fields mirroring Plan 3's GeneratedConfig.
        cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, "baseUrl", "Ljava/lang/String;", null, null).visitEnd();
        cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, "pluginId", "Ljava/lang/String;", null, null).visitEnd();
        cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, "publicKeys", "Ljava/util/Map;", null, null).visitEnd();
        cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, "activeKeyId", "Ljava/lang/String;", null, null).visitEnd();
        cw.visitField(Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL, "licenseKeyFileName", "Ljava/lang/String;", null, null).visitEnd();

        emitCtor(cw, owner);
        if (obfuscate) emitDecoder(cw, salt);
        emitLoad(cw, owner, cfg, obfuscate, salt);

        cw.visitEnd();
        return cw.toByteArray();
    }

    /** ctor(String,String,Map,String,String) assigning the five fields. */
    private static void emitCtor(ClassWriter cw, String owner) {
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;)V",
                null, null);
        mv.visitCode();
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        putField(mv, owner, 1, "baseUrl", "Ljava/lang/String;");
        putField(mv, owner, 2, "pluginId", "Ljava/lang/String;");
        putField(mv, owner, 3, "publicKeys", "Ljava/util/Map;");
        putField(mv, owner, 4, "activeKeyId", "Ljava/lang/String;");
        putField(mv, owner, 5, "licenseKeyFileName", "Ljava/lang/String;");
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    private static void putField(MethodVisitor mv, String owner, int arg, String name, String desc) {
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitVarInsn(Opcodes.ALOAD, arg);
        mv.visitFieldInsn(Opcodes.PUTFIELD, owner, name, desc);
    }

    /** static GeneratedConfig load() building the map + config from baked constants. */
    private static void emitLoad(ClassWriter cw, String owner, InjectConfig cfg,
                                 boolean obfuscate, byte[] salt) {
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "load",
                "()L" + owner + ";", null, null);
        mv.visitCode();

        // LinkedHashMap map = new LinkedHashMap();  -> local 0
        mv.visitTypeInsn(Opcodes.NEW, "java/util/LinkedHashMap");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/util/LinkedHashMap", "<init>", "()V", false);
        mv.visitVarInsn(Opcodes.ASTORE, 0);

        for (Map.Entry<String, String> e : cfg.publicKeys().entrySet()) {
            mv.visitVarInsn(Opcodes.ALOAD, 0);
            pushString(mv, e.getKey(), obfuscate, salt, owner);
            pushString(mv, e.getValue(), obfuscate, salt, owner);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/LinkedHashMap", "put",
                    "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", false);
            mv.visitInsn(Opcodes.POP);
        }

        // return new GeneratedConfig(baseUrl, pluginId, map, activeKeyId, licenseKeyFileName);
        mv.visitTypeInsn(Opcodes.NEW, owner);
        mv.visitInsn(Opcodes.DUP);
        pushString(mv, cfg.baseUrl(), obfuscate, salt, owner);
        pushString(mv, cfg.pluginId(), obfuscate, salt, owner);
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        pushString(mv, cfg.activeKeyId(), obfuscate, salt, owner);
        pushString(mv, cfg.licenseKeyFileName(), obfuscate, salt, owner);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, owner, "<init>",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/lang/String;Ljava/lang/String;)V", false);
        mv.visitInsn(Opcodes.ARETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
    }

    /** Pushes a String onto the stack: plain LDC, or XOR-decode of a baked byte[] via d([B). */
    private static void pushString(MethodVisitor mv, String value, boolean obfuscate,
                                   byte[] salt, String owner) {
        if (value == null) {
            mv.visitInsn(Opcodes.ACONST_NULL);
            return;
        }
        if (!obfuscate) {
            mv.visitLdcInsn(value);
            return;
        }
        byte[] enc = xor(value.getBytes(java.nio.charset.StandardCharsets.UTF_8), salt);
        // new byte[]{...}
        pushByteArray(mv, enc);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, owner, "d", "([B)Ljava/lang/String;", false);
    }

    private static void pushByteArray(MethodVisitor mv, byte[] data) {
        pushInt(mv, data.length);
        mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
        for (int i = 0; i < data.length; i++) {
            mv.visitInsn(Opcodes.DUP);
            pushInt(mv, i);
            pushInt(mv, data[i]);
            mv.visitInsn(Opcodes.BASTORE);
        }
    }

    private static void pushInt(MethodVisitor mv, int v) {
        if (v >= -1 && v <= 5) {
            mv.visitInsn(Opcodes.ICONST_0 + v);
        } else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) {
            mv.visitIntInsn(Opcodes.BIPUSH, v);
        } else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) {
            mv.visitIntInsn(Opcodes.SIPUSH, v);
        } else {
            mv.visitLdcInsn(v);
        }
    }

    /** private static String d(byte[] enc) { XOR with salt; new String(bytes, UTF_8) } */
    private static void emitDecoder(ClassWriter cw, byte[] salt) {
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "d",
                "([B)Ljava/lang/String;", null, null);
        mv.visitCode();
        // byte[] s = new byte[]{salt...}  -> local 1
        pushByteArray(mv, salt);
        mv.visitVarInsn(Opcodes.ASTORE, 1);
        // for (int i=0;i<enc.length;i++) enc[i] ^= s[i % s.length];  i -> local 2
        pushInt(mv, 0);
        mv.visitVarInsn(Opcodes.ISTORE, 2);
        org.objectweb.asm.Label top = new org.objectweb.asm.Label();
        org.objectweb.asm.Label end = new org.objectweb.asm.Label();
        mv.visitLabel(top);
        mv.visitVarInsn(Opcodes.ILOAD, 2);
        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitInsn(Opcodes.ARRAYLENGTH);
        mv.visitJumpInsn(Opcodes.IF_ICMPGE, end);
        // enc[i] = (byte)(enc[i] ^ s[i % s.length])
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
    }

    private static byte[] xor(byte[] data, byte[] salt) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) out[i] = (byte) (data[i] ^ salt[i % salt.length]);
        return out;
    }
}
