package io.qamelo.secrets.domain.pki;

import java.util.List;

public record CertificateIssueRequest(
        String roleName,
        String commonName,
        List<String> altNames,
        List<String> ipSans,
        String ttl) {
}
