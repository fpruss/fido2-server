package org.pruss.fido2server.data;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.UserIdentity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import javax.persistence.PersistenceException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest
public class ApplicationUserTest {

    @Autowired
    private TestEntityManager entityManager;

    @Test
    public void test_that_username_must_be_unique() {
        UserIdentity identity1 = UserIdentity.builder().name("not-unique").displayName("testuser").id(new ByteArray(new byte[1])).build();
        UserIdentity identity2 = UserIdentity.builder().name("not-unique").displayName("testuser").id(new ByteArray(new byte[1])).build();
        ApplicationUser user1 = new ApplicationUser(identity1);
        ApplicationUser user2 = new ApplicationUser(identity2);

        entityManager.persistAndFlush(user1);

        assertThatThrownBy(() -> entityManager.persistAndFlush(user2)).isInstanceOf(PersistenceException.class);
    }

    @Test
    public void test_to_user_identity() {
        UserIdentity identity = UserIdentity.builder().name("testuser").displayName("testuser").id(new ByteArray(new byte[1])).build();
        UserIdentity retrievedIdentity = new ApplicationUser(identity).toUserIdentity();

        assertThat(identity).isEqualTo(retrievedIdentity);
    }
}
