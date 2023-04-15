package bizserver.security.model;

import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class User {
    private String username;
    private String password;
    private String code;

    public User(String username, String password, String code) {
        this.username = username;
        this.password = password;
        this.code = code;
    }

    public static User usernamePassword(String username, String password) {
        return new User(username, password, null);
    }

    public static User usernameCode(String username, String code) {
        return new User(username, null, code);
    }
}
