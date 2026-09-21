package dev.podatek.worker;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/** Protects a ZIP package without ever loading or executing plugin classes. */
public final class PackageProtector {
    private static final int MAX_ENTRIES = 10_000;
    private static final long MAX_UNCOMPRESSED = 2L * 1024 * 1024 * 1024;
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String GUARD_NAME = "PodatekPackGuard";

    private PackageProtector() {}

    public record Result(byte[] archive, String buildId, int pluginCount,
                         int skippedCount, String manifestSha256) {}

    public static Result protect(byte[] source, InjectConfig cfg) {
        Map<String, byte[]> entries = readZip(source);
        List<Map<String, Object>> manifestPlugins = new ArrayList<>();
        List<String> managedNames = new ArrayList<>();
        int skipped = 0;

        for (Map.Entry<String, byte[]> entry : new ArrayList<>(entries.entrySet())) {
            String path = entry.getKey();
            if (!path.toLowerCase().endsWith(".jar")) continue;
            Map<String, byte[]> jarEntries;
            try {
                jarEntries = readZip(entry.getValue());
            } catch (RuntimeException ex) {
                throw new InjectException(422, "uszkodzony JAR w paczce: " + path);
            }
            if (!jarEntries.containsKey("plugin.yml")) {
                if (jarEntries.containsKey("paper-plugin.yml")) {
                    throw new InjectException(422,
                            "plugin paper-only nie jest jeszcze wspierany: " + path);
                }
                skipped++;
                continue;
            }
            try {
                JarModel model = JarModel.read(entry.getValue());
                if (!model.descriptor().hasClassicMain || model.descriptor().name == null
                        || GUARD_NAME.equals(model.descriptor().name)) {
                    throw new InjectException(422, "nieprawidlowy plugin.yml w: " + path);
                }
                String sourceHash = sha256(entry.getValue());
                byte[] protectedJar = addGuardDependency(entry.getValue());
                entries.put(path, protectedJar);
                managedNames.add(model.descriptor().name);
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("path", path);
                row.put("name", model.descriptor().name);
                row.put("sourceSha256", sourceHash);
                row.put("protectedSha256", sha256(protectedJar));
                row.put("size", protectedJar.length);
                manifestPlugins.add(row);
            } catch (InjectException ex) {
                throw ex;
            } catch (RuntimeException ex) {
                throw new InjectException(422, "nie mozna zabezpieczyc pluginu: " + path);
            }
        }
        if (managedNames.isEmpty()) {
            throw new InjectException(422, "paczka nie zawiera zadnego klasycznego pluginu Bukkit/Paper");
        }

        entries.put("plugins/PodatekPackGuard.jar", PackGuardEmitter.build(cfg, managedNames));
        entries.put("plugins/PodatekPackGuard/license.key",
                ("# Wklej klucz licencji paczki w nastepnej linii.\n").getBytes(StandardCharsets.UTF_8));

        String buildId = UUID.randomUUID().toString();
        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("format", "PODATEK-PACK-1");
        manifest.put("packageId", cfg.pluginId());
        manifest.put("buildId", buildId);
        manifest.put("createdAt", Instant.now().toString());
        manifest.put("guard", "plugins/PodatekPackGuard.jar");
        manifest.put("plugins", manifestPlugins);
        manifest.put("skippedJarCount", skipped);
        try {
            byte[] manifestBytes = JSON.writerWithDefaultPrettyPrinter().writeValueAsBytes(manifest);
            entries.put("PodatekPack/manifest.json", manifestBytes);
            byte[] archive = writeZip(entries);
            return new Result(archive, buildId, managedNames.size(), skipped, sha256(manifestBytes));
        } catch (Exception ex) {
            throw new InjectException(500, "nie mozna zapisac manifestu paczki");
        }
    }

    private static byte[] addGuardDependency(byte[] jar) {
        Map<String, byte[]> entries = readZip(jar);
        byte[] raw = entries.get("plugin.yml");
        if (raw == null) return jar;
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        Yaml yaml = new Yaml(options);
        Object loaded = yaml.load(new String(raw, StandardCharsets.UTF_8));
        if (!(loaded instanceof Map<?, ?> sourceMap)) return jar;
        Map<String, Object> descriptor = new LinkedHashMap<>();
        for (Map.Entry<?, ?> item : sourceMap.entrySet()) {
            descriptor.put(String.valueOf(item.getKey()), item.getValue());
        }
        List<String> depends = new ArrayList<>();
        Object existing = descriptor.get("depend");
        if (existing instanceof Iterable<?> values) {
            for (Object value : values) depends.add(String.valueOf(value));
        } else if (existing instanceof String value && !value.isBlank()) {
            depends.add(value);
        }
        if (!depends.contains(GUARD_NAME)) depends.add(GUARD_NAME);
        descriptor.put("depend", depends);
        entries.put("plugin.yml", yaml.dump(descriptor).getBytes(StandardCharsets.UTF_8));
        return writeZip(entries);
    }

    static Map<String, byte[]> readZip(byte[] bytes) {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        Set<String> normalizedNames = new HashSet<>();
        long total = 0;
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (entry.isDirectory()) continue;
                String name = safeName(entry.getName());
                if (!normalizedNames.add(name.toLowerCase())) {
                    throw new InjectException(400, "duplikat sciezki w ZIP: " + name);
                }
                if (entries.size() >= MAX_ENTRIES) throw new InjectException(413, "za duzo plikow w archiwum");
                ByteArrayOutputStream data = new ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                int read;
                while ((read = zip.read(buffer)) != -1) {
                    total += read;
                    if (total > MAX_UNCOMPRESSED) throw new InjectException(413, "rozpakowana paczka przekracza 2 GB");
                    data.write(buffer, 0, read);
                }
                entries.put(name, data.toByteArray());
            }
        } catch (InjectException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InjectException(400, "nieprawidlowe archiwum ZIP");
        }
        if (entries.isEmpty()) throw new InjectException(400, "puste archiwum ZIP");
        return entries;
    }

    static byte[] writeZip(Map<String, byte[]> entries) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            try (ZipOutputStream zip = new ZipOutputStream(output)) {
                for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                    zip.putNextEntry(new ZipEntry(safeName(entry.getKey())));
                    zip.write(entry.getValue());
                    zip.closeEntry();
                }
            }
            return output.toByteArray();
        } catch (Exception ex) {
            throw new InjectException(500, "nie mozna zapisac archiwum ZIP");
        }
    }

    private static String safeName(String name) {
        String normalized = name.replace('\\', '/');
        if (normalized.startsWith("/") || normalized.matches("^[A-Za-z]:.*")) {
            throw new InjectException(400, "niedozwolona sciezka bezwzgledna w ZIP");
        }
        for (String part : normalized.split("/")) {
            if (part.equals("..")) throw new InjectException(400, "niedozwolona sciezka '..' w ZIP");
        }
        return normalized;
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}
