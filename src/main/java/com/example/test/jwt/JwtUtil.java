package com.example.test.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {

    // JWT 토큰 만료 시간 (1시간, 단위: 밀리초)
    private final long EXPIRE_TIME = 60 * 60 * 1000;

    // 서명에 사용할 비밀키 (HMAC-SHA256 알고리즘용)
    // 실제 운영 환경에서는 외부 설정파일 또는 환경변수에서 관리하는 것이 안전합니다.
    private static final SecretKey secretKey = Keys.hmacShaKeyFor(
            "your-256-bit-secret-key-which-is-very-secure!".getBytes()
    );

    /**
     * JWT 토큰 생성 메서드
     * @param userName - 토큰에 담을 사용자 이름 (주체, subject)
     * @param role - 사용자 역할 정보 (claim 으로 저장)
     * @return 생성된 JWT 토큰 문자열
     */
    public String generateToken(String userName, String role) {
        return Jwts.builder()
                .setSubject(userName)  // 토큰 주체(subject) 설정: 사용자 이름
                .claim("role", role)   // 사용자 권한 정보를 claim에 추가
                .setIssuedAt(new Date()) // 토큰 발행 시간 설정
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE_TIME)) // 만료 시간 설정 (현재 시간 + 1시간)
                .signWith(secretKey, SignatureAlgorithm.HS256) // 비밀키와 알고리즘으로 서명
                .compact(); // 토큰을 문자열로 압축하여 반환
    }

    /**
     * JWT 토큰에서 모든 클레임(정보) 추출
     * @param token - JWT 토큰 문자열
     * @return Claims - 토큰에 담긴 정보 객체
     */
    public Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey) // 토큰 서명 검증에 사용할 키 설정
                .build()
                .parseClaimsJws(token)    // 토큰 파싱 및 검증
                .getBody();               // 클레임 반환
    }

    /**
     * 토큰 유효성 검사 메서드
     * 만료되었거나 변조된 토큰은 false 반환
     * @param token - JWT 토큰 문자열
     * @return 유효하면 true, 그렇지 않으면 false
     */
    public boolean isTokenValid(String token) {
        try {
            extractClaims(token); // 예외 없이 파싱되면 유효한 토큰
            return true;
        } catch (Exception e) {
            return false; // 만료, 서명 오류 등 예외 발생 시 유효하지 않음
        }
    }

    /**
     * 토큰에서 사용자 이름(subject) 추출
     * @param token - JWT 토큰 문자열
     * @return 토큰 내 사용자 이름
     */
    public String getUsername(String token) {
        return extractClaims(token).getSubject();
    }

    /**
     * 토큰에서 사용자 역할(role) 정보 추출
     * @param token - JWT 토큰 문자열
     * @return 토큰 내 역할 정보
     */
    public String getRole(String token) {
        return extractClaims(token).get("role", String.class);
    }
}

