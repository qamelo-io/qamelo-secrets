package io.qamelo.secrets.domain.error;

public record ErrorResponse(String error, String message, int status) {
}
