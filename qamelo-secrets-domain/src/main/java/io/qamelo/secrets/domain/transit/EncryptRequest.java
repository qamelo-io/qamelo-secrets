package io.qamelo.secrets.domain.transit;

public record EncryptRequest(String keyName, String plaintext) {
}
