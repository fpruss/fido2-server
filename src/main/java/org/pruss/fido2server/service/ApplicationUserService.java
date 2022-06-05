package org.pruss.fido2server.service;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.UserIdentity;
import lombok.AllArgsConstructor;
import org.pruss.fido2server.data.ApplicationUser;
import org.pruss.fido2server.data.CredentialRepositoryImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.util.Optional;

@Service
@AllArgsConstructor(onConstructor = @__(@Autowired))
public class ApplicationUserService {

    private final CredentialRepositoryImpl credentialRepositoryImpl;

    public void requireExists(ApplicationUser user) {
        if (getUser(user.getHandle()).isEmpty()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "User " + user.getUsername() + " does not exist. Please register.");
        }
    }

    public void requireExists(String username) {
        if (getUser(username).isEmpty()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "User " + username + " does not exist. Please register.");
        }
    }

    public void requireDoesNotExist(String username) {
        if (getUser(username).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username " + username + " already exists. Choose a new name.");
        }
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
