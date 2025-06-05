package com.example.test.config;

import com.example.test.jwt.JwtAuthFilter;
import com.example.test.jwt.JwtUtil;
import com.example.test.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableMethodSecurity  // 메서드 단위 권한 검사 활성화 (예: @PreAuthorize)
@RequiredArgsConstructor  // final 필드를 생성자 주입해주는 롬복 어노테이션
public class SecurityConfig {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;

    /**
     * HTTP 보안 필터 체인 설정
     * Spring Security 동작의 핵심 설정
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF 보호 비활성화 (REST API에선 일반적으로 비활성화)
                .csrf(AbstractHttpConfigurer::disable)

                // 세션 상태를 Stateless로 설정 (JWT 기반 인증이므로 세션 사용 안 함)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 기본 폼 로그인 비활성화 (JWT 토큰 인증 사용)
                .formLogin(AbstractHttpConfigurer::disable)

                // HTTP Basic 인증 비활성화 (JWT 토큰 인증 사용)
                .httpBasic(AbstractHttpConfigurer::disable)

                // 권한 요청 규칙 설정
                .authorizeHttpRequests(auth -> auth
                        // 루트 경로 ("/") 및 "/auth/**" 하위 경로는 인증 없이 접근 허용
                        .requestMatchers("/").permitAll()
                        .requestMatchers("/auth/**").permitAll()
                        // 그 외 모든 요청은 인증 필요
                        .anyRequest().authenticated()
                )

                // 커스텀 JWT 인증 필터를 UsernamePasswordAuthenticationFilter 이전에 추가
                .addFilterBefore(new JwtAuthFilter(userDetailsService, jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // 설정된 httpSecurity 객체로 SecurityFilterChain 빈 생성 후 반환
        return http.build();
    }

    /**
     * 인증 관리자 빈 등록
     * Spring Security 인증 처리의 핵심 컴포넌트
     */
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        // HttpSecurity 내부에 있는 AuthenticationManagerBuilder 가져오기
        AuthenticationManagerBuilder authManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);

        // 사용자 인증 정보를 가져올 UserDetailsService 등록 및 비밀번호 암호화 방식 설정
        authManagerBuilder
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());

        // 인증 관리자 빌드하여 반환
        return authManagerBuilder.build();
    }

    /**
     * 비밀번호 인코더 빈 등록
     * BCrypt 알고리즘을 사용해 비밀번호를 해싱함
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * CORS 설정 빈 등록
     * 외부 도메인에서 API 호출 허용 설정
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // 모든 출처(origin) 허용 (보안상 필요에 따라 제한 가능)
        config.addAllowedOriginPattern("*");

        // 모든 HTTP 메서드 허용 (GET, POST, PUT, DELETE 등)
        config.addAllowedMethod("*");

        // 모든 헤더 허용
        config.addAllowedHeader("*");

        // 쿠키 등 자격 증명 전송 허용 설정
        config.setAllowCredentials(true);

        // CORS 설정을 모든 경로에 적용
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }
}


