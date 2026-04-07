package io.qamelo.secrets.app.auth;

import io.qamelo.secrets.app.security.MtlsAuthFilter;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MtlsAuthFilterTest {

    @Mock ContainerRequestContext requestContext;
    @Mock UriInfo uriInfo;
    @Mock X509Certificate clientCert;

    MtlsAuthFilter filter;

    @BeforeEach
    void setUp() {
        filter = new MtlsAuthFilter();
        lenient().when(requestContext.getUriInfo()).thenReturn(uriInfo);
    }

    @Test
    void shouldPassWithValidClientCert() throws Exception {
        when(uriInfo.getPath()).thenReturn("/api/v1/internal/secrets/pki/issue");
        X509Certificate[] certs = {clientCert};
        when(requestContext.getProperty("jakarta.servlet.request.X509Certificate")).thenReturn(certs);
        when(clientCert.getSubjectX500Principal()).thenReturn(new X500Principal("CN=qamelo-connectivity.qamelo-system.svc.cluster.local"));
        when(clientCert.getSubjectAlternativeNames()).thenReturn(null);

        filter.filter(requestContext);

        verify(requestContext, never()).abortWith(any());
        verify(requestContext).setProperty(eq(MtlsAuthFilter.CALLER_IDENTITY_ATTRIBUTE),
                eq("qamelo-connectivity.qamelo-system.svc.cluster.local"));
    }

    @Test
    void shouldExtractSanOverCn() throws Exception {
        when(uriInfo.getPath()).thenReturn("/api/v1/internal/secrets/kv/test");
        X509Certificate[] certs = {clientCert};
        when(requestContext.getProperty("jakarta.servlet.request.X509Certificate")).thenReturn(certs);
        when(clientCert.getSubjectAlternativeNames()).thenReturn(List.of(List.of(2, "qamelo-server.qamelo-system.svc.cluster.local")));

        filter.filter(requestContext);

        verify(requestContext).setProperty(eq(MtlsAuthFilter.CALLER_IDENTITY_ATTRIBUTE),
                eq("qamelo-server.qamelo-system.svc.cluster.local"));
    }

    @Test
    void shouldRejectRequestWithoutCert() throws Exception {
        when(uriInfo.getPath()).thenReturn("/api/v1/internal/secrets/pki/issue");
        when(requestContext.getProperty("jakarta.servlet.request.X509Certificate")).thenReturn(null);
        when(requestContext.getProperty("javax.servlet.request.X509Certificate")).thenReturn(null);

        filter.filter(requestContext);

        ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
        verify(requestContext).abortWith(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo(401);
    }

    @Test
    void shouldSkipNonInternalPaths() throws Exception {
        when(uriInfo.getPath()).thenReturn("/q/health/ready");

        filter.filter(requestContext);

        verify(requestContext, never()).abortWith(any());
        verify(requestContext, never()).getProperty(any());
    }

    @Test
    void shouldRejectEmptyCertArray() throws Exception {
        when(uriInfo.getPath()).thenReturn("/api/v1/internal/secrets/transit/encrypt");
        when(requestContext.getProperty("jakarta.servlet.request.X509Certificate")).thenReturn(new X509Certificate[0]);
        when(requestContext.getProperty("javax.servlet.request.X509Certificate")).thenReturn(null);

        filter.filter(requestContext);

        ArgumentCaptor<Response> captor = ArgumentCaptor.forClass(Response.class);
        verify(requestContext).abortWith(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo(401);
    }
}
