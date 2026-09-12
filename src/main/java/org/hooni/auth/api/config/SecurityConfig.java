package org.hooni.auth.api.config;

import lombok.RequiredArgsConstructor;
import org.hooni.auth.api.security.CustomAuthenticationFilter;
import org.hooni.auth.api.security.OriginValidationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomAuthenticationFilter authenticationFilter;
    private final OriginValidationFilter originValidationFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 상태 변경 요청은 OriginValidationFilter와 SameSite 쿠키로 교차 사이트 요청을 차단한다.
                // 향후 허용 Origin 범위를 넓히거나 SameSite=None을 사용하면 CSRF 토큰도 적용해야 한다.
                .csrf(csrf -> csrf.disable())
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .logout(logout -> logout.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests
                        // refresh/logout은 Access Token 만료 상태에서도 실행되어야 하므로 공개한다.
                        // 실제 Refresh Token 검증과 폐기는 서비스 계층에서 수행한다.
                        .requestMatchers(
                                "/auth/login",
                                "/auth/register",
                                "/auth/register/exists",
                                "/auth/refresh",
                                "/auth/logout",
                                "/auth/session",
                                "/oauth2/jwks",
                                "/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/"
                        ).permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(originValidationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    FilterRegistrationBean<OriginValidationFilter> originValidationFilterRegistration(
            OriginValidationFilter filter
    ) {
        FilterRegistrationBean<OriginValidationFilter> registration = new FilterRegistrationBean<>(filter);
        // SecurityFilterChain 안에서만 실행해 순서가 달라지는 이중 등록을 방지한다.
        registration.setEnabled(false);
        return registration;
    }
}
