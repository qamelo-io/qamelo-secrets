package io.qamelo.secrets.domain.spi;

import io.qamelo.secrets.domain.ssh.SshOtpRequest;
import io.qamelo.secrets.domain.ssh.SshOtpResponse;
import io.qamelo.secrets.domain.ssh.SshSignRequest;
import io.qamelo.secrets.domain.ssh.SshSignResponse;
import io.smallrye.mutiny.Uni;

/**
 * SSH secret engine — signed certificates and one-time passwords.
 */
public interface SshEngine {

    Uni<SshSignResponse> signPublicKey(SshSignRequest request);

    Uni<SshOtpResponse> generateOtp(SshOtpRequest request);
}
