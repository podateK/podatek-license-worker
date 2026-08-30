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

/** Javalin HTTP surface: POST /inject (bearer) + GET /healthz. */
public final class Server {

    static final long MAX_JAR_BYTES = 100L * 1024 * 1024; // 100 MB
    private static final ObjectMapper JSON = new ObjectMapper();

    private Server() {}

    public static Javalin create(int port, String secret) {
        Javalin app = Javalin.create(cfg -> {
            cfg.http.maxRequestSize = MAX_JAR_BYTES + (1L * 1024 * 1024); // headroom for multipart envelope
            cfg.showJavalinBanner = false;
        });

        app.before("/inject", ctx -> {
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

        app.exception(InjectException.class, (e, ctx) ->
                ctx.status(e.status()).json(Map.of("error", e.getMessage())));
        app.exception(JarModel.JarReadException.class, (e, ctx) ->
                ctx.status(400).json(Map.of("error", "nieprawidlowe archiwum jar")));
        app.exception(Exception.class, (e, ctx) ->
                ctx.status(500).json(Map.of("error", "wewnetrzny blad workera")));

        return app.start(port);
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
