package dev.podatek.worker;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;

/** Loads synthesized/relocated class bytes and reflectively drives them, for tests. */
final class TestClassLoaders {
    private TestClassLoaders() {}

    /** A child-first classloader mapping internal-name -> class bytes. */
    static final class ByteArrayClassLoader extends ClassLoader {
        private final Map<String, byte[]> byInternalName;
        ByteArrayClassLoader(Map<String, byte[]> byInternalName, ClassLoader parent) {
            super(parent);
            this.byInternalName = byInternalName;
        }
        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            String internal = name.replace('.', '/');
            byte[] bytes = byInternalName.get(internal);
            if (bytes == null) bytes = byInternalName.get(internal + ".class");
            if (bytes == null) throw new ClassNotFoundException(name);
            return defineClass(name, bytes, 0, bytes.length);
        }
        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            synchronized (getClassLoadingLock(name)) {
                Class<?> c = findLoadedClass(name);
                if (c == null) {
                    String internal = name.replace('.', '/');
                    if (byInternalName.containsKey(internal) || byInternalName.containsKey(internal + ".class")) {
                        c = findClass(name);
                    } else {
                        c = super.loadClass(name, false);
                    }
                }
                if (resolve) resolveClass(c);
                return c;
            }
        }
    }

    /** Build a loader over the given map (keys may be internal names with or without .class). */
    static ByteArrayClassLoader loader(Map<String, byte[]> classes) {
        java.util.Map<String, byte[]> norm = new java.util.LinkedHashMap<>();
        // First pass: .class-suffixed entries. Second pass: plain keys override (emitted config wins).
        for (Map.Entry<String, byte[]> e : classes.entrySet()) {
            String k = e.getKey();
            if (k.endsWith(".class")) norm.put(k.substring(0, k.length() - ".class".length()), e.getValue());
        }
        for (Map.Entry<String, byte[]> e : classes.entrySet()) {
            String k = e.getKey();
            if (!k.endsWith(".class")) norm.put(k, e.getValue());
        }
        return new ByteArrayClassLoader(norm, TestClassLoaders.class.getClassLoader());
    }

    static Object invokeStaticLoad(Map<String, byte[]> classes, String binaryName) throws Exception {
        ByteArrayClassLoader cl = loader(classes);
        Class<?> c = Class.forName(binaryName, true, cl);
        Method m = c.getMethod("load");
        return m.invoke(null);
    }

    static Object field(Object obj, String name) throws Exception {
        Field f = obj.getClass().getField(name);
        return f.get(obj);
    }
}
