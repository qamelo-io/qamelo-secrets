package io.qamelo.secrets.domain.spi;

import io.qamelo.secrets.domain.transit.DecryptRequest;
import io.qamelo.secrets.domain.transit.DecryptResponse;
import io.qamelo.secrets.domain.transit.EncryptRequest;
import io.qamelo.secrets.domain.transit.EncryptResponse;
import io.smallrye.mutiny.Uni;

/**
 * Transit secret engine — encrypt/decrypt without key export.
 */
public interface TransitEngine {

    Uni<EncryptResponse> encrypt(EncryptRequest request);

    Uni<DecryptResponse> decrypt(DecryptRequest request);
}
