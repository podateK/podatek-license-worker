package dev.podatek.worker;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;

import java.util.LinkedHashMap;
import java.util.Map;

/** Shades + relocates Plan 3 client classes under a random per-build prefix. */
public final class Relocator {

    private Relocator() {}

    /**
     * Remaps every internal name {@code dev/podatek/lic} -> {@code prefix} in both class bytes
     * and entry paths. References to {@code org/bukkit/**} and {@code java/**} are left untouched.
     *
     * @param prefix a single internal-name segment, e.g. {@code "p1234"} (no trailing slash)
     */
    public static Map<String, byte[]> relocate(Map<String, byte[]> payload, String prefix) {
        Remapper remapper = new PackageRemapper(ClientPayload.BASE, prefix);
        Map<String, byte[]> out = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> e : payload.entrySet()) {
            byte[] remapped = remapClass(e.getValue(), remapper);
            String newKey = remapPath(e.getKey(), prefix);
            out.put(newKey, remapped);
        }
        return out;
    }

    private static String remapPath(String path, String prefix) {
        String base = ClientPayload.BASE + "/";
        if (path.startsWith(base)) {
            return prefix + "/" + path.substring(base.length());
        }
        if (path.equals(ClientPayload.BASE)) return prefix;
        return path;
    }

    private static byte[] remapClass(byte[] bytes, Remapper remapper) {
        ClassReader cr = new ClassReader(bytes);
        // No frame recomputation: pure name remapping preserves stack maps, keeps major version.
        ClassWriter cw = new ClassWriter(0);
        ClassRemapper cv = new ClassRemapper(cw, remapper);
        cr.accept(cv, 0);
        return cw.toByteArray();
    }

    /** Remaps the base package prefix in internal names AND in String constants (dotted + slash). */
    static final class PackageRemapper extends Remapper {
        private final String baseSlash;         // dev/podatek/lic
        private final String baseDot;           // dev.podatek.lic
        private final String prefixSlash;       // p1234
        private final String prefixDot;         // p1234

        PackageRemapper(String baseSlash, String prefix) {
            this.baseSlash = baseSlash;
            this.baseDot = baseSlash.replace('/', '.');
            this.prefixSlash = prefix;
            this.prefixDot = prefix.replace('/', '.');
        }

        @Override
        public String map(String internalName) {
            if (internalName.equals(baseSlash)) return prefixSlash;
            if (internalName.startsWith(baseSlash + "/")) {
                return prefixSlash + "/" + internalName.substring(baseSlash.length() + 1);
            }
            return internalName;
        }

        @Override
        public Object mapValue(Object value) {
            if (value instanceof String) {
                String s = (String) value;
                if (s.contains(baseDot)) {
                    s = s.replace(baseDot, prefixDot);
                }
                if (s.contains(baseSlash)) {
                    s = s.replace(baseSlash, prefixSlash);
                }
                return s;
            }
            return super.mapValue(value);
        }
    }
}
