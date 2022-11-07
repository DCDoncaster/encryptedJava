package GWSWE.Demo.APIDemo;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.BCrypt.Version;

import java.util.HashMap;
import java.util.Map;

public class AuthenticationService {
    //TODO: This needs hiding
    private static final int COST_FACTOR = 6;
    private final BCrypt.Hasher hashAlg = BCrypt.with(Version.VERSION_2Y);
    //short term memory for storing user for testing
    //TODO: Create a data storage solution
    private Map<String, String> credentialStore = new HashMap<>();
    public boolean encryptAndStore(String username, String password) {
    //generate new string with hashedpassword
        String hashedPassword = hashAlg.hashToString(COST_FACTOR, password.toCharArray());
        credentialStore.put(username, hashedPassword);
        return true;
    }
    public boolean verifyPassword(String username, String password) {
        if(!credentialStore.containsKey(username)){
            return false;
        }
        String hashedPassword = credentialStore.get(username);
        Boolean isMatch = BCrypt.verifyer().verify(password.toCharArray(), hashedPassword).verified;
        return isMatch;
    }
}
