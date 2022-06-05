package org.pruss.fido2server.data;

import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.data.AttestedCredentialData;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.pruss.fido2server.util.ByteArrayAttributeConverter;

import javax.persistence.*;
import java.util.Optional;

@Entity
@Getter
@NoArgsConstructor
public class Authenticator {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Lob
    @Column(nullable = false)
    @Convert(converter = ByteArrayAttributeConverter.class)
    private ByteArray credentialId;

    @Lob
    @Column(nullable = false)
    @Convert(converter = ByteArrayAttributeConverter.class)
    private ByteArray publicKey;

    @ManyToOne
    private ApplicationUser applicationUser;

    /**
     * recommended by W3C. If Count decreases, that could be a sign of a malicious Authenticator
     */
    @Column(nullable = false)
    private Long count;

    /**
     * aaguid should be provided by authenticator. Defines the type of credential used.
     * Can be used to verify the authenticators make and model. Can be used to deny access
     * for outdated unsecure authenticators
     */
    @Lob
    @Column
    @Convert(converter = ByteArrayAttributeConverter.class)
    private ByteArray aaguid;

    public Authenticator(RegistrationResult result,
                         AuthenticatorAttestationResponse response,
                         ApplicationUser applicationUser) {
        Optional<AttestedCredentialData> attestationData = response.getAttestation()
                .getAuthenticatorData()
                .getAttestedCredentialData();
        this.credentialId = result.getKeyId().getId();
        this.publicKey = result.getPublicKeyCose();
        this.aaguid = attestationData.get().getAaguid();
        this.count = result.getSignatureCount();
        this.applicationUser = applicationUser;
    }
}
