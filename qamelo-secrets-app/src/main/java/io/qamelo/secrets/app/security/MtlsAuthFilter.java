package io.qamelo.secrets.app.security;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.security.cert.X509Certificate;

/**
 * JAX-RS filter that validates mTLS client certificates on internal endpoints.
 * Replaces SharedSecretAuthFilter — extracts caller identity from client cert
 * CN/SAN for structured audit logging. No inter-service authorization.
 */
@Provider
@Priority(Priorities.AUTHENTICATION - 10)
public class MtlsAuthFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(MtlsAuthFilter.class);
    private static final String INTERNAL_PATH_PREFIX = "/api/v1/internal/";
    public static final String CALLER_IDENTITY_ATTRIBUTE = "qamelo.caller.identity";

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String path = requestContext.getUriInfo().getPath();
        if (!path.startsWith(INTERNAL_PATH_PREFIX)) {
            return;
        }

        X509Certificate[] certs = (X509Certificate[]) requestContext
                .getProperty("jakarta.servlet.request.X509Certificate");
        if (certs == null || certs.length == 0) {
            certs = (X509Certificate[]) requestContext
                    .getProperty("javax.servlet.request.X509Certificate");
        }

        if (certs == null || certs.length == 0) {
            LOG.warnf("No client certificate on internal path: %s", path);
            requestContext.abortWith(unauthorizedResponse());
            return;
        }

        String callerIdentity = extractCallerIdentity(certs[0]);
        requestContext.setProperty(CALLER_IDENTITY_ATTRIBUTE, callerIdentity);
        LOG.debugf("Internal request authenticated: caller=%s, path=%s", callerIdentity, path);
    }

    private String extractCallerIdentity(X509Certificate cert) {
        try {
            if (cert.getSubjectAlternativeNames() != null) {
                for (var san : cert.getSubjectAlternativeNames()) {
                    if ((Integer) san.get(0) == 2) {
                        return (String) san.get(1);
                    }
                }
            }
        } catch (Exception e) {
            LOG.debugf("Failed to extract SAN: %s", e.getMessage());
        }
        String dn = cert.getSubjectX500Principal().getName();
        for (String part : dn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return dn;
    }

    private Response unauthorizedResponse() {
        return Response.status(Response.Status.UNAUTHORIZED)
                .type(MediaType.APPLICATION_JSON)
                .entity("{\"error\":\"unauthorized\",\"message\":\"Client certificate required for internal endpoints\"}")
                .build();
    }
}
