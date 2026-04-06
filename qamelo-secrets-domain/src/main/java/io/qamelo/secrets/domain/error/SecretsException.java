package io.qamelo.secrets.domain.error;

public class SecretsException extends RuntimeException {

    private final SecretsErrorCode code;

    public SecretsException(SecretsErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public SecretsException(SecretsErrorCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public SecretsErrorCode code() {
        return code;
    }
}
