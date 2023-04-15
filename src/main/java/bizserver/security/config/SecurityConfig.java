package bizserver.security.config;

import bizserver.security.filter.InitialAuthenticationFilter;
import bizserver.security.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final InitialAuthenticationFilter initialAuthenticationFilter;

    @Bean
    SecurityFilterChain httpSecurity(HttpSecurity httpSecurity) throws Exception {
        // csrf 보호를 비활성화한다.
        httpSecurity.csrf().disable();
        // 두 맞춤형 필터를 필터 체인에 추가한다.
        httpSecurity.addFilterAt(initialAuthenticationFilter, BasicAuthenticationFilter.class);
        httpSecurity.addFilterAfter(jwtAuthenticationFilter, BasicAuthenticationFilter.class);
        // 모든 요청은 인증되어야 한다.
        httpSecurity.authorizeHttpRequests().anyRequest().authenticated();

        return httpSecurity.build();
    }
}
