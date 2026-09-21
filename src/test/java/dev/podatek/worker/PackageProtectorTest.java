package dev.podatek.worker;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class PackageProtectorTest {
    private static InjectConfig config() {
        return new InjectConfig("http://localhost/api/license", "survival-pack",
                Map.of("k1", "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="),
                "k1", "license.key");
    }

    @Test void protectsPluginJarsAndAddsGuardAndManifest() throws Exception {
        byte[] plugin = Fixtures.pluginJar("com.demo.DemoPlugin", Fixtures.DEMO_YML);
        byte[] archive = zip(Map.of("plugins/Demo.jar", plugin, "server.properties", new byte[0]));
        PackageProtector.Result result = PackageProtector.protect(archive, config());
        Map<String, byte[]> out = PackageProtector.readZip(result.archive());

        assertEquals(1, result.pluginCount());
        assertTrue(out.containsKey("plugins/PodatekPackGuard.jar"));
        assertTrue(out.containsKey("plugins/PodatekPackGuard/license.key"));
        assertTrue(out.containsKey("PodatekPack/manifest.json"));
        String protectedYml = JarModel.read(out.get("plugins/Demo.jar")).descriptor().rawYaml;
        assertTrue(protectedYml.contains("PodatekPackGuard"));
        JarModel guard = JarModel.read(out.get("plugins/PodatekPackGuard.jar"));
        assertEquals("PodatekPackGuard", guard.descriptor().name);
        assertNotNull(guard.descriptor().mainClass);
    }

    @Test void rejectsZipSlip() throws Exception {
        byte[] archive = zip(Map.of("../escape.jar", new byte[]{1}));
        InjectException ex = assertThrows(InjectException.class,
                () -> PackageProtector.protect(archive, config()));
        assertEquals(400, ex.status());
    }

    @Test void rejectsArchiveWithoutPlugins() throws Exception {
        byte[] archive = zip(Map.of("readme.txt", "x".getBytes(StandardCharsets.UTF_8)));
        InjectException ex = assertThrows(InjectException.class,
                () -> PackageProtector.protect(archive, config()));
        assertEquals(422, ex.status());
    }

    @Test void rejectsPaperOnlyPluginInsteadOfShippingItUnprotected() throws Exception {
        byte[] paperPlugin = zip(Map.of(
                "paper-plugin.yml",
                "name: PaperOnly\nmain: com.demo.PaperOnly\nversion: 1.0\n"
                        .getBytes(StandardCharsets.UTF_8)));
        byte[] archive = zip(Map.of("plugins/PaperOnly.jar", paperPlugin));
        InjectException ex = assertThrows(InjectException.class,
                () -> PackageProtector.protect(archive, config()));
        assertEquals(422, ex.status());
        assertTrue(ex.getMessage().contains("paper-only"));
    }

    @Test void rejectsMalformedJarInsteadOfShippingItUnprotected() throws Exception {
        byte[] archive = zip(Map.of("plugins/Broken.jar", new byte[]{1, 2, 3}));
        InjectException ex = assertThrows(InjectException.class,
                () -> PackageProtector.protect(archive, config()));
        assertEquals(422, ex.status());
        assertTrue(ex.getMessage().contains("uszkodzony JAR"));
    }

    private static byte[] zip(Map<String, byte[]> entries) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return out.toByteArray();
    }
}
