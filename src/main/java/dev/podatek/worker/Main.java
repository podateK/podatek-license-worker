package dev.podatek.worker;

public class Main {
    public static void main(String[] args) {
        int port = envInt("PORT", 8080);
        String secret = System.getenv("INJECT_WORKER_SECRET");
        if (secret == null || secret.isEmpty()) {
            System.err.println("FATAL: INJECT_WORKER_SECRET nie jest ustawiony");
            System.exit(1);
        }
        Server.create(port, secret);
        System.out.println("podatek-license-worker up on :" + port
                + " (client " + ClientPayload.version() + ")");
    }

    private static int envInt(String name, int def) {
        String v = System.getenv(name);
        if (v == null || v.isEmpty()) return def;
        try { return Integer.parseInt(v.trim()); } catch (NumberFormatException e) { return def; }
    }
}
