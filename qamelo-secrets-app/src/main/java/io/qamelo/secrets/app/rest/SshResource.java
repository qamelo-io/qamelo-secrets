package io.qamelo.secrets.app.rest;

import io.qamelo.secrets.domain.spi.SshEngine;
import io.qamelo.secrets.domain.ssh.SshOtpRequest;
import io.qamelo.secrets.domain.ssh.SshOtpResponse;
import io.qamelo.secrets.domain.ssh.SshSignRequest;
import io.qamelo.secrets.domain.ssh.SshSignResponse;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("/api/v1/internal/secrets/ssh")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class SshResource {

    @Inject
    SshEngine sshEngine;

    @POST
    @Path("sign")
    public Uni<SshSignResponse> sign(SshSignRequest request) {
        return sshEngine.signPublicKey(request);
    }

    @POST
    @Path("otp")
    public Uni<SshOtpResponse> otp(SshOtpRequest request) {
        return sshEngine.generateOtp(request);
    }
}
