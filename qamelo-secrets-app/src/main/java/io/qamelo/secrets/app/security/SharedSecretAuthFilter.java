package io.qamelo.secrets.app.security;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

@Provider
@Priority(Priorities.AUTHENTICATION - 10)
public class SharedSecretAuthFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(SharedSecretAuthFilter.class);
    private static final String INTERNAL_PATH_PREFIX = "/api/v1/internal/";

    private final String internalSecret;

    public SharedSecretAuthFilter(@ConfigProperty(name = "qamelo.internal.secret") String internalSecret) {
        this.internalSecret = internalSecret;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String path = requestContext.getUriInfo().getPath();

        if (!path.startsWith(INTERNAL_PATH_PREFIX)) {
            return;
        }

        String authorization = requestContext.getHeaderString("Authorization");
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            LOG.warnf("Missing or malformed Authorization header on internal path: %s", path);
            requestContext.abortWith(unauthorizedResponse());
            return;
        }

        String token = authorization.substring(7);
        if (!internalSecret.equals(token)) {
            LOG.warnf("Invalid internal token on path: %s", path);
            requestContext.abortWith(unauthorizedResponse());
        }
    }

    private Response unauthorizedResponse() {
        return Response.status(Response.Status.UNAUTHORIZED)
                .type(MediaType.APPLICATION_JSON)
                .entity("{\"error\":\"ACCESS_DENIED\",\"message\":\"Invalid or missing internal token\",\"status\":401}")
                .build();
    }
}
