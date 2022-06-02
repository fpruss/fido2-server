package org.pruss.fido2server.data;

import com.yubico.webauthn.data.ByteArray;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AuthenticatorRepository extends CrudRepository<Authenticator, Long> {
    Optional<Authenticator> findByCredentialId(ByteArray credentialId);
    List<Authenticator> findAllByApplicationUser(ApplicationUser applicationUser);
    List<Authenticator> findAllByCredentialId(ByteArray credentialId);
}
