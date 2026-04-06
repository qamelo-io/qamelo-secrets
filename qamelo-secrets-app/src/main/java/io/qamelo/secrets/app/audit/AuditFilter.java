package io.qamelo.secrets.app.audit;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.time.Instant;

@Provider
public class AuditFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private static final Logger AUDIT = Logger.getLogger("io.qamelo.secrets.audit");
    private static final String START_TIME = "qamelo.audit.startTime";

    @Override
    public void filter(ContainerRequestContext requestContext) {
        requestContext.setProperty(START_TIME, System.nanoTime());
    }

    @Override
    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        String path = requestContext.getUriInfo().getPath();

        // Only audit secret operation endpoints
        if (!path.startsWith("/api/v1/internal/")) {
            return;
        }

        Object startObj = requestContext.getProperty(START_TIME);
        long durationMs = 0;
        if (startObj instanceof Long startNanos) {
            durationMs = (System.nanoTime() - startNanos) / 1_000_000;
        }

        String method = requestContext.getMethod();
        String op = resolveOperation(method, path);
        int status = responseContext.getStatus();
        String ts = Instant.now().toString();

        AUDIT.infof("{\"ts\":\"%s\",\"op\":\"%s\",\"path\":\"%s\",\"status\":%d,\"duration_ms\":%d}",
                ts, op, path, status, durationMs);
    }

    private String resolveOperation(String method, String path) {
        if (path.contains("/kv/")) {
            return switch (method) {
                case "GET" -> path.contains("/metadata") ? "kv.metadata" : "kv.read";
                case "PUT" -> "kv.write";
                case "DELETE" -> "kv.delete";
                default -> "kv.unknown";
            };
        }
        if (path.contains("/health")) {
            return "health.check";
        }
        return method.toLowerCase() + "." + path;
    }
}
