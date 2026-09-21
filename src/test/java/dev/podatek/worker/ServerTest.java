package dev.podatek.worker;

import io.javalin.Javalin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayOutputStream;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ServerTest {

    private Javalin app;
    private static final String SECRET = "s3cret";

    private int port() { return app.port(); }

    @AfterEach void stop() { if (app != null) app.stop(); }

    private HttpResponse<byte[]> postInject(String bearer, byte[] jar, String configJson) throws Exception {
        String boundary = "----plw" + System.nanoTime();
        byte[] body = multipart(boundary, "jar", "master.jar", jar, configJson);
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port() + "/inject"))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        if (bearer != null) b.header("Authorization", "Bearer " + bearer);
        return HttpClient.newHttpClient().send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private HttpResponse<byte[]> postPackage(String bearer, byte[] archive, String configJson) throws Exception {
        String boundary = "----plw" + System.nanoTime();
        byte[] body = multipart(boundary, "archive", "package.zip", archive, configJson);
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + port() + "/protect-package"))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        if (bearer != null) b.header("Authorization", "Bearer " + bearer);
        return HttpClient.newHttpClient().send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private static byte[] multipart(String boundary, String fieldName, String fileName,
                                    byte[] file, String configJson) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        String dd = "--";
        String crlf = "\r\n";
        if (file != null) {
            bos.write((dd + boundary + crlf).getBytes(StandardCharsets.UTF_8));
            bos.write(("Content-Disposition: form-data; name=\"" + fieldName
                    + "\"; filename=\"" + fileName + "\"" + crlf)
                    .getBytes(StandardCharsets.UTF_8));
            bos.write(("Content-Type: application/octet-stream" + crlf + crlf).getBytes(StandardCharsets.UTF_8));
            bos.write(file);
            bos.write(crlf.getBytes(StandardCharsets.UTF_8));
        }
        if (configJson != null) {
            bos.write((dd + boundary + crlf).getBytes(StandardCharsets.UTF_8));
            bos.write(("Content-Disposition: form-data; name=\"config\"" + crlf + crlf)
                    .getBytes(StandardCharsets.UTF_8));
            bos.write(configJson.getBytes(StandardCharsets.UTF_8));
            bos.write(crlf.getBytes(StandardCharsets.UTF_8));
        }
        bos.write((dd + boundary + dd + crlf).getBytes(StandardCharsets.UTF_8));
        return bos.toByteArray();
    }

    private static final String CONFIG_JSON =
            "{\"baseUrl\":\"https://auth4.podatek.dev/api/license\",\"pluginId\":\"demo\"," +
            "\"publicKeys\":{\"k1\":\"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\"}," +
            "\"activeKeyId\":\"k1\",\"licenseKeyFileName\":\"license.key\"}";

    @Test void healthzReportsClientVersion() throws Exception {
        app = Server.create(0, SECRET);
        HttpResponse<String> res = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder().uri(URI.create("http://localhost:" + port() + "/healthz")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, res.statusCode());
        assertTrue(res.body().contains("\"ok\":true"));
        assertTrue(res.body().contains("1.0.0"));
    }

    @Test void injectRequiresBearer() throws Exception {
        app = Server.create(0, SECRET);
        HttpResponse<byte[]> res = postInject(null,
                Fixtures.pluginJar("com.demo.DemoPlugin", Fixtures.DEMO_YML), CONFIG_JSON);
        assertEquals(401, res.statusCode());
    }

    @Test void injectReturnsArchiveWithHeaders() throws Exception {
        app = Server.create(0, SECRET);
        HttpResponse<byte[]> res = postInject(SECRET,
                Fixtures.pluginJar("com.demo.DemoPlugin", Fixtures.DEMO_YML), CONFIG_JSON);
        assertEquals(200, res.statusCode());
        assertEquals("application/java-archive",
                res.headers().firstValue("Content-Type").orElse(""));
        assertEquals("shim", res.headers().firstValue("X-Inject-Hook-Mode").orElse(""));
        assertTrue(res.headers().firstValue("X-Inject-Reloc-Prefix").orElse("").startsWith("p"));
        assertTrue(res.headers().firstValue("X-Inject-Build-Id").isPresent());
        // response body is a valid jar with the shim
        JarModel out = JarModel.read(res.body());
        String prefix = res.headers().firstValue("X-Inject-Reloc-Prefix").get();
        assertTrue(out.entries().containsKey(prefix + "/LicenseShim.class"));
    }

    @Test void nonJarIsClientError() throws Exception {
        app = Server.create(0, SECRET);
        HttpResponse<byte[]> res = postInject(SECRET,
                "this is not a jar".getBytes(StandardCharsets.UTF_8), CONFIG_JSON);
        assertEquals(400, res.statusCode());
    }

    @Test void packageProtectionRequiresBearer() throws Exception {
        app = Server.create(0, SECRET);
        byte[] plugin = Fixtures.pluginJar("com.demo.DemoPlugin", Fixtures.DEMO_YML);
        HttpResponse<byte[]> res = postPackage(null,
                PackageProtector.writeZip(Map.of("plugins/Demo.jar", plugin)), CONFIG_JSON);
        assertEquals(401, res.statusCode());
    }

    @Test void packageProtectionReturnsGuardManifestAndHeaders() throws Exception {
        app = Server.create(0, SECRET);
        byte[] plugin = Fixtures.pluginJar("com.demo.DemoPlugin", Fixtures.DEMO_YML);
        HttpResponse<byte[]> res = postPackage(SECRET,
                PackageProtector.writeZip(Map.of("plugins/Demo.jar", plugin)), CONFIG_JSON);
        assertEquals(200, res.statusCode());
        assertEquals("application/zip", res.headers().firstValue("Content-Type").orElse(""));
        assertEquals("1", res.headers().firstValue("X-Pack-Plugin-Count").orElse(""));
        assertTrue(res.headers().firstValue("X-Pack-Build-Id").isPresent());
        Map<String, byte[]> archive = PackageProtector.readZip(res.body());
        assertTrue(archive.containsKey("plugins/PodatekPackGuard.jar"));
        assertTrue(archive.containsKey("PodatekPack/manifest.json"));
    }
}
