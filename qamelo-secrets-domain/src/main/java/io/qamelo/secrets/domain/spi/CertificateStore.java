package io.qamelo.secrets.domain.spi;

import io.qamelo.secrets.domain.pki.CaCertificateResponse;
import io.qamelo.secrets.domain.pki.CertificateInfo;
import io.qamelo.secrets.domain.pki.CertificateIssueRequest;
import io.qamelo.secrets.domain.pki.IssuedCertificate;
import io.smallrye.mutiny.Uni;

import java.util.List;

/**
 * PKI secret engine — X.509 certificate issuance and lifecycle.
 */
public interface CertificateStore {

    Uni<IssuedCertificate> issue(CertificateIssueRequest request);

    Uni<CertificateInfo> readCertificate(String serialNumber);

    Uni<Void> revoke(String serialNumber);

    Uni<CaCertificateResponse> getCaCertificate();

    Uni<List<CertificateInfo>> listExpiring(String within);
}
