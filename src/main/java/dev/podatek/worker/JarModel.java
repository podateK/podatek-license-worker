package dev.podatek.worker;

import org.yaml.snakeyaml.Yaml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/** Reads a plugin jar into memory, parses plugin.yml, and repackages. */
public final class JarModel {

    /** Parsed view of plugin.yml / paper-plugin.yml. */
    public static final class PluginDescriptor {
        public final String mainClass;
        public final String name;
        public final String apiVersion;
        public final boolean hasClassicMain;
        public final String rawYaml;

        PluginDescriptor(String mainClass, String name, String apiVersion,
                         boolean hasClassicMain, String rawYaml) {
            this.mainClass = mainClass;
            this.name = name;
            this.apiVersion = apiVersion;
            this.hasClassicMain = hasClassicMain;
            this.rawYaml = rawYaml;
        }
    }

    private final Map<String, byte[]> entries;
    private final PluginDescriptor descriptor;

    private JarModel(Map<String, byte[]> entries, PluginDescriptor descriptor) {
        this.entries = entries;
        this.descriptor = descriptor;
    }

    public Map<String, byte[]> entries() { return entries; }

    public PluginDescriptor descriptor() { return descriptor; }

    /** Read all zip entries into a LinkedHashMap (preserving order) and parse the descriptor. */
    public static JarModel read(byte[] jar) {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(jar))) {
            ZipEntry e;
            byte[] buf = new byte[8192];
            while ((e = zis.getNextEntry()) != null) {
                if (e.isDirectory()) { zis.closeEntry(); continue; }
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                int n;
                while ((n = zis.read(buf)) != -1) bos.write(buf, 0, n);
                entries.put(e.getName(), bos.toByteArray());
                zis.closeEntry();
            }
        } catch (Exception ex) {
            throw new JarReadException("nie mozna odczytac archiwum jar: " + ex.getMessage(), ex);
        }
        return new JarModel(entries, parseDescriptor(entries));
    }

    private static PluginDescriptor parseDescriptor(Map<String, byte[]> entries) {
        boolean classic = true;
        byte[] ymlBytes = entries.get("plugin.yml");
        if (ymlBytes == null) {
            ymlBytes = entries.get("paper-plugin.yml");
            classic = false;
        }
        if (ymlBytes == null) {
            return new PluginDescriptor(null, null, null, false, null);
        }
        String raw = new String(ymlBytes, StandardCharsets.UTF_8);
        String main = null, name = null, apiVersion = null;
        try {
            Object loaded = new Yaml().load(raw);
            if (loaded instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> map = (Map<String, Object>) loaded;
                main = str(map.get("main"));
                name = str(map.get("name"));
                apiVersion = str(map.get("api-version"));
            }
        } catch (Exception ignore) {
            // malformed yaml -> treat as no descriptor
        }
        boolean hasClassicMain = classic && main != null && !main.isEmpty();
        return new PluginDescriptor(main, name, apiVersion, hasClassicMain, raw);
    }

    private static String str(Object o) { return o == null ? null : String.valueOf(o); }

    /** Repackage entries (deflate) preserving order. */
    public byte[] toBytes() {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (ZipOutputStream zos = new ZipOutputStream(bos)) {
                for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                    zos.putNextEntry(new ZipEntry(e.getKey()));
                    zos.write(e.getValue());
                    zos.closeEntry();
                }
            }
            return bos.toByteArray();
        } catch (Exception ex) {
            throw new JarReadException("nie mozna zapisac archiwum jar: " + ex.getMessage(), ex);
        }
    }

    /** Thrown on unreadable / malformed archives. */
    public static final class JarReadException extends RuntimeException {
        public JarReadException(String msg, Throwable cause) { super(msg, cause); }
    }
}
