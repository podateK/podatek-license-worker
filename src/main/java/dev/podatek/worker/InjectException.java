package dev.podatek.worker;

/** A client-facing injection failure carrying the HTTP status to return. */
public final class InjectException extends RuntimeException {
    private final int status;
    public InjectException(int status, String message) {
        super(message);
        this.status = status;
    }
    public int status() { return status; }
}
