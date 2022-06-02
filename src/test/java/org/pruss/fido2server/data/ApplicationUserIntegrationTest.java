package org.pruss.fido2server.data;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.UserIdentity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
public class ApplicationUserIntegrationTest {

    @Autowired
    private TestEntityManager entityManager;

    @Test
    public void test_save_user() {
        UserIdentity identity = UserIdentity.builder().name("testuser").displayName("testuser").id(new ByteArray(new byte[1])).build();
        ApplicationUser user = new ApplicationUser(identity);
        ApplicationUser savedUser = entityManager.persistAndFlush(user);

        assertThat(savedUser).isEqualTo(user);
    }

    @Test
    public void test_to_user_identity() {
        UserIdentity identity = UserIdentity.builder().name("testuser").displayName("testuser").id(new ByteArray(new byte[1])).build();
        UserIdentity retrievedIdentity = new ApplicationUser(identity).toUserIdentity();

        assertThat(identity).isEqualTo(retrievedIdentity);
    }
}
