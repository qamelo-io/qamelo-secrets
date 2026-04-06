package io.qamelo.secrets.app.rest;

import io.qamelo.secrets.domain.pki.CaCertificateResponse;
import io.qamelo.secrets.domain.pki.CertificateInfo;
import io.qamelo.secrets.domain.pki.CertificateIssueRequest;
import io.qamelo.secrets.domain.pki.IssuedCertificate;
import io.qamelo.secrets.domain.spi.CertificateStore;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;

import java.util.List;

@Path("/api/v1/internal/secrets/pki")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class PkiResource {

    @Inject
    CertificateStore certificateStore;

    @POST
    @Path("issue")
    public Uni<IssuedCertificate> issue(CertificateIssueRequest request) {
        return certificateStore.issue(request);
    }

    @GET
    @Path("cert/{serial}")
    public Uni<CertificateInfo> readCertificate(@PathParam("serial") String serial) {
        return certificateStore.readCertificate(serial);
    }

    @POST
    @Path("revoke")
    public Uni<Void> revoke(RevokeRequest request) {
        return certificateStore.revoke(request.serialNumber());
    }

    @GET
    @Path("ca")
    public Uni<CaCertificateResponse> getCaCertificate() {
        return certificateStore.getCaCertificate();
    }

    @GET
    @Path("certs/expiring")
    public Uni<List<CertificateInfo>> listExpiring(
            @QueryParam("within") @DefaultValue("30d") String within) {
        return certificateStore.listExpiring(within);
    }

    public record RevokeRequest(String serialNumber) {
    }
}
