package dev.podatek.worker;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.net.JarURLConnection;

/** Loads Plan 3 client class bytes ({@code dev/podatek/lic/**}) from the baked jar on the classpath. */
public final class ClientPayload {

    /** Base package of the Plan 3 client, internal (slash) form. */
    public static final String BASE = "dev/podatek/lic";

    private ClientPayload() {}

    /** Returns every {@code dev/podatek/lic/**.class} entry from the baked client jar. */
    public static Map<String, byte[]> classes() {
        Map<String, byte[]> out = new LinkedHashMap<>();
        JarFile jar = null;
        try {
            // Locate the jar that contains a known client class.
            URL url = ClientPayload.class.getClassLoader()
                    .getResource(BASE + "/LicenseVersion.class");
            if (url == null) {
                throw new IllegalStateException("baked client jar not found on classpath");
            }
            URLConnection conn = url.openConnection();
            if (conn instanceof JarURLConnection) {
                jar = ((JarURLConnection) conn).getJarFile();
            } else {
                throw new IllegalStateException("client classes are not in a jar: " + url);
            }
            java.util.Enumeration<JarEntry> en = jar.entries();
            while (en.hasMoreElements()) {
                JarEntry e = en.nextElement();
                String name = e.getName();
                if (e.isDirectory()) continue;
                if (!name.startsWith(BASE + "/")) continue;
                if (!name.endsWith(".class")) continue;
                try (InputStream is = jar.getInputStream(e)) {
                    out.put(name, readAll(is));
                }
            }
        } catch (Exception ex) {
            throw new RuntimeException("nie mozna wczytac payloadu Plan 3: " + ex.getMessage(), ex);
        }
        // Do NOT close the shared JarFile from a JarURLConnection (cached by the JVM).
        if (out.isEmpty()) throw new IllegalStateException("payload Plan 3 jest pusty");
        return out;
    }

    /** Reads the {@code LicenseVersion.VERSION} constant baked into the client jar. */
    public static String version() {
        try {
            Class<?> c = Class.forName("dev.podatek.lic.LicenseVersion");
            Object v = c.getField("VERSION").get(null);
            return String.valueOf(v);
        } catch (Throwable t) {
            return "unknown";
        }
    }

    private static byte[] readAll(InputStream is) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
        return bos.toByteArray();
    }
}
