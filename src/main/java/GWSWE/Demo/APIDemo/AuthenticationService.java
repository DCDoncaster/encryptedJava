package GWSWE.Demo.APIDemo;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.BCrypt.Version;

import java.util.HashMap;
import java.util.Map;

import io.github.cdimascio.dotenv.*;

public class AuthenticationService {

    private final BCrypt.Hasher hashAlg = BCrypt.with(Version.VERSION_2Y);

    //TODO: Create a data storage solution - This works for now as a short term storage while testing
    private final Map<String, String> credentialStore = new HashMap<>();

    public boolean encryptAndStore(String username, String password) {
    //generate new string with hashedPassword
        Dotenv dotenv = Dotenv.load();
        System.out.println(dotenv.get("COST_FACTOR"));

        String hashedPassword = hashAlg.hashToString(Integer.parseInt(dotenv.get("COST_FACTOR")), password.toCharArray());
        credentialStore.put(username, hashedPassword);
        return true;
    }

    public boolean verifyPassword(String username, String password) {
        if(!credentialStore.containsKey(username)){
            return false;
        }
        String hashedPassword = credentialStore.get(username);
        return BCrypt.verifyer().verify(password.toCharArray(), hashedPassword).verified;
    }
}
