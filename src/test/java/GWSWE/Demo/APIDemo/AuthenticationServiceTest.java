package GWSWE.Demo.APIDemo;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AuthenticationServiceTest {

    @Test
    public void givenUserNameAndPasswordShouldBeAbleToEncryptAndStore(){
        String username = "username";
        String password = "password";
        AuthenticationService authenticationService = new AuthenticationService();
        boolean isEncrypted = authenticationService.encryptAndStore(username, password);
        boolean isVerified = authenticationService.verifyPassword(username,password);
        assertTrue(isEncrypted);
        assertTrue(isVerified);
    }
    @Test
    public void refusesLoginWithIncorrectPassword(){
        String username = "username";
        String password = "password";
        AuthenticationService authenticationService = new AuthenticationService();
        authenticationService.encryptAndStore(username, password);
        boolean isNotVerified = authenticationService.verifyPassword(username,"password2");
        assertFalse(isNotVerified);
    }
}
