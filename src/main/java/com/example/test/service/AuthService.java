package com.example.test.service;

import com.example.test.domain.User;
import com.example.test.dto.LoginRequestDto;
import com.example.test.dto.SignUpRequestDto;
import com.example.test.jwt.JwtUtil;
import com.example.test.repository.UserRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, AuthenticationManager authenticationManager, JwtUtil jwtUtil, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
    }

    public ResponseEntity<?> login(LoginRequestDto loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        String token = jwtUtil.generateToken(
                authentication.getName(),
                authentication.getAuthorities().iterator().next().getAuthority()
        );

        // 쿠키 생성
        ResponseCookie cookie = ResponseCookie.from("token", token)
                .httpOnly(true)                     // JS에서 접근 불가
                .secure(true)                       // HTTPS에서만 전송 (개발 시 false 가능)
                .path("/")                          // 모든 경로에 적용
                .maxAge(60 * 60 * 24)               // 1일
                .sameSite("Lax")                    // 크로스 사이트 보안
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(Map.of("token", token)); // body에도 같이 내려줄 수 있음
    }


    @Transactional
    public ResponseEntity<Boolean> signUp(SignUpRequestDto signUpRequestDto) {
        String encodedPassword = passwordEncoder.encode(signUpRequestDto.getPassword());

        User user = User.builder()
                .userName(signUpRequestDto.getUsername())
                .password(encodedPassword)
                .role(signUpRequestDto.getRole())
                .build();

        userRepository.save(user);

        return ResponseEntity.ok(true);
    }
}
