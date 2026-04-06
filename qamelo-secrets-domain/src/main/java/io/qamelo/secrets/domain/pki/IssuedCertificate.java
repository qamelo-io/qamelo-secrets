package io.qamelo.secrets.domain.pki;

import java.time.Instant;

public record IssuedCertificate(
        String serialNumber,
        String certificatePem,
        String privateKeyPem,
        String issuingCaPem,
        String caChainPem,
        Instant expiration) {
}
