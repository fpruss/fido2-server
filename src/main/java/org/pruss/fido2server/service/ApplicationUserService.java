package org.pruss.fido2server.service;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.UserIdentity;
import lombok.AllArgsConstructor;
import org.pruss.fido2server.data.ApplicationUser;
import org.pruss.fido2server.data.CredentialRepositoryImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Optional;

@Service
@AllArgsConstructor(onConstructor = @__(@Autowired))
public class ApplicationUserService {

    private final CredentialRepositoryImpl credentialRepositoryImpl;

    public boolean doesNotExist(ApplicationUser user) {
        return getUser(user.getHandle()).isEmpty();
    }

    public boolean exists(String username) {
        return getUser(username).isPresent();
    }

    public ApplicationUser createApplicationUser(String username, String displayName) {
        UserIdentity userIdentity = UserIdentity.builder()
                .name(username)
                .displayName(displayName)
                .id(generateRandom())
                .build();
        return new ApplicationUser(userIdentity);
    }

    public Optional<ApplicationUser> getUser(ByteArray userHandle) {
        return Optional.ofNullable(credentialRepositoryImpl.getApplicationUserRepository().findByHandle(userHandle));
    }

    public Optional<ApplicationUser> getUser(String username) {
        return Optional.ofNullable(credentialRepositoryImpl.getApplicationUserRepository().findByUsername(username));
    }

    public void save(ApplicationUser user) {
        credentialRepositoryImpl.getApplicationUserRepository().save(user);
    }

    private ByteArray generateRandom() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return new ByteArray(bytes);
    }
}
