package io.qamelo.secrets.domain.pki;

import java.time.Instant;

public record CertificateInfo(String serialNumber, String certificatePem, Instant notAfter, boolean revoked) {
}
