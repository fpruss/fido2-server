package org.pruss.fido2server.data;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.util.stream.Collectors.*;

@Getter
@AllArgsConstructor(onConstructor = @__(@Autowired))
@Repository
public class RegistrationService implements CredentialRepository {

    private final ApplicationUserRepository applicationUserRepository;

    private final AuthenticatorRepository authenticatorRepository;

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        ApplicationUser user = applicationUserRepository.findByUsername(username);
        List<Authenticator> auth = authenticatorRepository.findAllByApplicationUser(user);
        return auth.stream()
                .map(credential ->
                        PublicKeyCredentialDescriptor.builder()
                                .id(credential.getCredentialId())
                                .build())
                .collect(toSet());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        ApplicationUser user = applicationUserRepository.findByUsername(username);
        return Optional.of(user.getHandle());
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        ApplicationUser user = applicationUserRepository.findByHandle(userHandle);
        return Optional.of(user.getUsername());
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        Optional<Authenticator> authenticator = authenticatorRepository.findByCredentialId(credentialId);
        return authenticator.map(credential ->
                RegisteredCredential.builder()
                        .credentialId(credential.getCredentialId())
                        .userHandle(credential.getApplicationUser().getHandle())
                        .publicKeyCose(credential.getPublicKey())
                        .signatureCount(credential.getCount())
                        .build()
        );
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        List<Authenticator> authenticators = authenticatorRepository.findAllByCredentialId(credentialId);
        return authenticators.stream()
                .map(credential ->
                        RegisteredCredential.builder()
                                .credentialId(credential.getCredentialId())
                                .userHandle(credential.getApplicationUser().getHandle())
                                .publicKeyCose(credential.getPublicKey())
                                .signatureCount(credential.getCount())
                                .build())
                .collect(toSet());
    }
}
