package io.qamelo.secrets.app.error;

import io.qamelo.secrets.domain.error.ErrorResponse;
import io.qamelo.secrets.domain.error.SecretsException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class SecretsExceptionMapper implements ExceptionMapper<SecretsException> {

    @Override
    public Response toResponse(SecretsException exception) {
        int status = mapStatus(exception);
        return Response.status(status)
                .entity(new ErrorResponse(exception.code().name(), exception.getMessage(), status))
                .build();
    }

    private int mapStatus(SecretsException exception) {
        if (exception.getMessage() != null && exception.getMessage().startsWith("CAS conflict")) {
            return 409;
        }
        return switch (exception.code()) {
            case SECRET_NOT_FOUND -> 404;
            case ACCESS_DENIED -> 403;
            case VAULT_UNAVAILABLE -> 503;
            case LEASE_EXPIRED -> 410;
            case INVALID_REQUEST -> 400;
            case RATE_LIMITED -> 429;
            case UPSTREAM_ERROR -> 502;
        };
    }
}
