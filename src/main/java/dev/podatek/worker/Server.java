package dev.podatek.worker;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.UnauthorizedResponse;
import io.javalin.http.UploadedFile;

import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Iterator;
import java.util.Map;

/** Javalin HTTP surface: plugin and package protection endpoints + health check. */
public final class Server {

    static final long MAX_JAR_BYTES = 100L * 1024 * 1024; // 100 MB
    static final long MAX_PACKAGE_BYTES = 500L * 1024 * 1024; // 500 MB
    private static final ObjectMapper JSON = new ObjectMapper();

    private Server() {}

    public static Javalin create(int port, String secret) {
        Javalin app = Javalin.create(cfg -> {
            cfg.http.maxRequestSize = MAX_PACKAGE_BYTES + (1L * 1024 * 1024); // multipart headroom
            cfg.showJavalinBanner = false;
        });

        app.before("/inject", ctx -> {
            String auth = ctx.header("Authorization");
            if (auth == null || !auth.equals("Bearer " + secret)) {
                throw new UnauthorizedResponse("brak lub bledny Bearer token");
            }
        });
        app.before("/protect-package", ctx -> {
            String auth = ctx.header("Authorization");
            if (auth == null || !auth.equals("Bearer " + secret)) {
                throw new UnauthorizedResponse("brak lub bledny Bearer token");
            }
        });

        app.get("/healthz", ctx -> {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("ok", true);
            body.put("clientVersion", ClientPayload.version());
            ctx.json(body);
        });

        app.post("/inject", Server::handleInject);
        app.post("/protect-package", Server::handleProtectPackage);

        app.exception(InjectException.class, (e, ctx) ->
                ctx.status(e.status()).json(Map.of("error", e.getMessage())));
        app.exception(JarModel.JarReadException.class, (e, ctx) ->
                ctx.status(400).json(Map.of("error", "nieprawidlowe archiwum jar")));
        app.exception(Exception.class, (e, ctx) ->
                ctx.status(500).json(Map.of("error", "wewnetrzny blad workera")));

        return app.start(port);
    }

    private static void handleProtectPackage(Context ctx) throws Exception {
        UploadedFile archive = ctx.uploadedFile("archive");
        if (archive == null) {
            throw new InjectException(400, "brak pliku 'archive' w multipart");
        }
        if (archive.size() > MAX_PACKAGE_BYTES) {
            throw new InjectException(413, "paczka przekracza limit 500 MB");
        }
        byte[] source;
        try (InputStream is = archive.content()) {
            source = is.readAllBytes();
        }

        String configRaw = ctx.formParam("config");
        if (configRaw == null || configRaw.isBlank()) {
            throw new InjectException(400, "brak pola 'config'");
        }
        InjectConfig cfg = parseConfig(configRaw);
        PackageProtector.Result result = PackageProtector.protect(source, cfg);

        ctx.status(200);
        ctx.contentType("application/zip");
        ctx.header("X-Pack-Build-Id", result.buildId());
        ctx.header("X-Pack-Plugin-Count", Integer.toString(result.pluginCount()));
        ctx.header("X-Pack-Skipped-Count", Integer.toString(result.skippedCount()));
        ctx.header("X-Pack-Manifest-Sha256", result.manifestSha256());
        ctx.result(result.archive());
    }

    private static void handleInject(Context ctx) throws Exception {
        UploadedFile jar = ctx.uploadedFile("jar");
        if (jar == null) {
            throw new InjectException(400, "brak pliku 'jar' w multipart");
        }
        if (jar.size() > MAX_JAR_BYTES) {
            throw new InjectException(413, "jar przekracza limit 100 MB");
        }
        byte[] master;
        try (InputStream is = jar.content()) {
            master = is.readAllBytes();
        }

        String configRaw = ctx.formParam("config");
        if (configRaw == null || configRaw.isBlank()) {
            throw new InjectException(400, "brak pola 'config'");
        }
        InjectConfig cfg = parseConfig(configRaw);

        Injector.Result r = Injector.inject(master, cfg);

        ctx.status(200);
        ctx.contentType("application/java-archive");
        ctx.header("X-Inject-Hook-Mode", r.hookMode);
        ctx.header("X-Inject-Reloc-Prefix", r.relocPrefix);
        ctx.header("X-Inject-Build-Id", r.buildId);
        if (r.warnings != null && !r.warnings.isEmpty()) {
            ctx.header("X-Inject-Warnings", r.warnings);
        }
        ctx.result(r.jar);
    }

    static InjectConfig parseConfig(String json) {
        try {
            JsonNode n = JSON.readTree(json);
            String baseUrl = text(n, "baseUrl");
            String pluginId = text(n, "pluginId");
            String activeKeyId = text(n, "activeKeyId");
            String licenseKeyFileName = text(n, "licenseKeyFileName");
            Map<String, String> keys = new LinkedHashMap<>();
            JsonNode pk = n.get("publicKeys");
            if (pk != null && pk.isObject()) {
                Iterator<String> it = pk.fieldNames();
                while (it.hasNext()) {
                    String k = it.next();
                    keys.put(k, pk.get(k).asText());
                }
            }
            if (baseUrl == null || baseUrl.isEmpty()) {
                throw new InjectException(400, "config.baseUrl jest wymagany");
            }
            if (keys.isEmpty()) {
                throw new InjectException(400, "config.publicKeys nie moze byc puste");
            }
            return new InjectConfig(baseUrl, pluginId, keys, activeKeyId, licenseKeyFileName);
        } catch (InjectException e) {
            throw e;
        } catch (Exception e) {
            throw new InjectException(400, "nieprawidlowy JSON w polu 'config'");
        }
    }

    private static String text(JsonNode n, String field) {
        JsonNode v = n.get(field);
        return (v == null || v.isNull()) ? null : v.asText();
    }
}
