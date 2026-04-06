package io.qamelo.secrets.domain.transit;

public record DecryptRequest(String keyName, String ciphertext) {
}
