package org.pruss.fido2server.data;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.UserIdentity;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.pruss.fido2server.util.ByteArrayAttributeConverter;

import javax.persistence.*;

@Entity
@Getter
@NoArgsConstructor
public class ApplicationUser {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String displayName;

    @Lob
    @Column(nullable = false, length = 64)
    @Convert(converter = ByteArrayAttributeConverter.class)
    private ByteArray handle;

    public ApplicationUser(UserIdentity user) {
        this.handle = user.getId();
        this.username = user.getName();
        this.displayName = user.getDisplayName();
    }

    public UserIdentity toUserIdentity() {
        return UserIdentity.builder()
                .name(getUsername())
                .displayName(getDisplayName())
                .id(getHandle())
                .build();
    }

    @Override
    public String toString() {
        return "ApplicationUser{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", displayName='" + displayName + '\'' +
                ", handle=" + handle +
                '}';
    }
}
