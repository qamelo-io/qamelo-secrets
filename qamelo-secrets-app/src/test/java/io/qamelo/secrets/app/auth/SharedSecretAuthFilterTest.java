package io.qamelo.secrets.app.auth;

import io.qamelo.secrets.app.security.SharedSecretAuthFilter;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class SharedSecretAuthFilterTest {

    private static final String SECRET = "test-shared-secret";

    private SharedSecretAuthFilter filter;
    private ContainerRequestContext ctx;
    private UriInfo uriInfo;

    @BeforeEach
    void setUp() {
        filter = new SharedSecretAuthFilter(SECRET);
        ctx = mock(ContainerRequestContext.class);
        uriInfo = mock(UriInfo.class);
        when(ctx.getUriInfo()).thenReturn(uriInfo);
    }

    @Test
    void validSecretPassesThrough() {
        when(uriInfo.getPath()).thenReturn("/api/v1/internal/secrets/kv/some/path");
        when(ctx.getHeaderString("Authorization")).thenReturn("Bearer " + SECRET);

        filter.filter(ctx);

        verify(ctx, never()).abortWith(any());
    }

    @Test
    void missingAuthorizationHeaderReturns401() {
        when(uriInfo.getPath()).thenReturn("/api/v1/internal/secrets/kv/some/path");
        when(ctx.getHeaderString("Authorization")).thenReturn(null);

        filter.filter(ctx);

        verify(ctx).abortWith(argThat(response ->
                response.getStatus() == Response.Status.UNAUTHORIZED.getStatusCode()));
    }

    @Test
    void wrongSecretReturns401() {
        when(uriInfo.getPath()).thenReturn("/api/v1/internal/secrets/kv/some/path");
        when(ctx.getHeaderString("Authorization")).thenReturn("Bearer wrong-secret");

        filter.filter(ctx);

        verify(ctx).abortWith(argThat(response ->
                response.getStatus() == Response.Status.UNAUTHORIZED.getStatusCode()));
    }

    @Test
    void malformedAuthorizationHeaderReturns401() {
        when(uriInfo.getPath()).thenReturn("/api/v1/internal/secrets/kv/some/path");
        when(ctx.getHeaderString("Authorization")).thenReturn("Basic dXNlcjpwYXNz");

        filter.filter(ctx);

        verify(ctx).abortWith(argThat(response ->
                response.getStatus() == Response.Status.UNAUTHORIZED.getStatusCode()));
    }

    @Test
    void nonInternalPathSkipsFilter() {
        when(uriInfo.getPath()).thenReturn("/q/health/ready");

        filter.filter(ctx);

        verify(ctx, never()).abortWith(any());
        verify(ctx, never()).getHeaderString(any());
    }
}
