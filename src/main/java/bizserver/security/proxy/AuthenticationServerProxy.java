package bizserver.security.proxy;

import bizserver.security.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
@RequiredArgsConstructor
public class AuthenticationServerProxy {
    private final RestTemplate restTemplate;

    @Value("${auth.server.base.url}")
    private String baseUrl;

    /**
     * 인증서버로 인증 요청한다.
     * @param username
     * @param password
     */

    public void sendAuth(String username, String password) {
        String url = baseUrl + "/user/auth";
        var user = User.usernamePassword(username, password);
        restTemplate.postForEntity(url, user, Void.class);
    }

    /**
     * 인증서버로 OTP 값 검증 인증한다.
     * @param username
     * @param code
     */
    public void sendOtp(String username, String code) {
        String url = baseUrl + "/otp/check";
        var user = User.usernameCode(username, code);
        restTemplate.postForEntity(url, user, Void.class);
    }

}
