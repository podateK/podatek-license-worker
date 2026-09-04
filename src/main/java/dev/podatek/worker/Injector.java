package dev.podatek.worker;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Orchestrates the full injection pipeline: parse -> relocate -> emit config -> hook -> assemble. */
public final class Injector {

    private static final SecureRandom RNG = new SecureRandom();
    private static final Pattern MAIN_LINE = Pattern.compile("(?m)^([ \\t]*main[ \\t]*:[ \\t]*).*$");

    private Injector() {}

    public static final class Result {
        public final byte[] jar;
        public final String hookMode;
        public final String relocPrefix;
        public final String buildId;
        public final String warnings;
        public final String clientVersion;
        Result(byte[] jar, String hookMode, String relocPrefix, String buildId,
               String warnings, String clientVersion) {
            this.jar = jar;
            this.hookMode = hookMode;
            this.relocPrefix = relocPrefix;
            this.buildId = buildId;
            this.warnings = warnings;
            this.clientVersion = clientVersion;
        }
    }

    public static Result inject(byte[] masterJar, InjectConfig cfg) {
        JarModel host = JarModel.read(masterJar);
        JarModel.PluginDescriptor d = host.descriptor();

        if (d.mainClass == null || d.mainClass.isEmpty()) {
            if (d.rawYaml == null) {
                throw new InjectException(400, "brak plugin.yml (ani paper-plugin.yml)");
            }
            // plugin.yml/paper-plugin.yml present but no classic 'main' -> paper-only, unsupported.
            throw new InjectException(422, "brak classic 'main' (paper-only plugin nieobslugiwany w MVP)");
        }

        String relocPrefix = "p" + randomHex(12);
        byte[] salt = new byte[16];
        RNG.nextBytes(salt);
        String buildId = UUID.randomUUID().toString();

        Map<String, byte[]> payload = Relocator.relocate(ClientPayload.classes(), relocPrefix);
        byte[] emittedConfig = ConfigEmitter.emit(relocPrefix, cfg, salt);
        Hooker.HookResult hook = Hooker.hook(host, relocPrefix);

        // Assemble: host entries first (preserve order), then payload, then overrides.
        Map<String, byte[]> out = new LinkedHashMap<>(host.entries());
        out.putAll(payload);
        out.put(relocPrefix + "/GeneratedConfig.class", emittedConfig);
        out.putAll(hook.addedOrPatched()); // shim class, or patched host main (asm-insert)

        String warnings = "";
        if ("shim".equals(hook.mode)) {
            byte[] ymlBytes = out.get("plugin.yml");
            if (ymlBytes != null) {
                String yml = new String(ymlBytes, StandardCharsets.UTF_8);
                String rewritten = rewriteMain(yml, hook.newMainClass);
                out.put("plugin.yml", rewritten.getBytes(StandardCharsets.UTF_8));
            } else {
                warnings = "shim mode bez plugin.yml do przepisania";
            }
        }

        // Obfuscate ONLY our injected classes (relocPrefix/**, minus shaded lib and GeneratedConfig).
        // Runs last, on the assembled map, so it can never touch host entries.
        out = Obfuscator.obfuscate(out, relocPrefix, salt);

        JarModel assembled = JarModelFrom(out);
        return new Result(assembled.toBytes(), hook.mode, relocPrefix, buildId,
                warnings, ClientPayload.version());
    }

    /** Textually rewrite the plugin.yml 'main:' value, preserving the rest of the YAML. */
    static String rewriteMain(String yml, String newMain) {
        Matcher m = MAIN_LINE.matcher(yml);
        if (m.find()) {
            // Keep the captured "main: " prefix (group 1), replace only the value.
            return m.replaceFirst("$1" + Matcher.quoteReplacement(newMain));
        }
        return yml;
    }

    private static JarModel JarModelFrom(Map<String, byte[]> entries) {
        // Build a jar from entries then re-read (keeps a single code path for descriptor/repack).
        return JarModel.read(toJar(entries));
    }

    private static byte[] toJar(Map<String, byte[]> entries) {
        try {
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            try (java.util.zip.ZipOutputStream zos = new java.util.zip.ZipOutputStream(bos)) {
                for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                    zos.putNextEntry(new java.util.zip.ZipEntry(e.getKey()));
                    zos.write(e.getValue());
                    zos.closeEntry();
                }
            }
            return bos.toByteArray();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static String randomHex(int nChars) {
        byte[] b = new byte[(nChars + 1) / 2];
        RNG.nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.substring(0, nChars);
    }
}
