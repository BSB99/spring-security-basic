package com.example.test.jwt;

import com.example.test.service.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAuthFilter extends OncePerRequestFilter {

    private final CustomUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    // 생성자: UserDetailsService와 JwtUtil을 주입받음
    public JwtAuthFilter(CustomUserDetailsService userDetailsService, JwtUtil jwtUtil) {
        this.userDetailsService = userDetailsService;
        this.jwtUtil = jwtUtil;
    }

    /**
     * 실제 필터 동작을 수행하는 메서드
     * 모든 요청마다 실행되며 JWT 토큰을 검사해 인증 처리 수행
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String token = null;

        // 1) HTTP 요청 헤더 "Authorization" 에서 JWT 토큰을 가져온다.
        // "Bearer "로 시작하는 경우에만 토큰으로 간주하고 앞의 "Bearer " 부분을 제거
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);  // "Bearer " 이후의 토큰 문자열 추출
        }

        // 2) 만약 헤더에 토큰이 없으면 쿠키에서 "token" 이름의 쿠키를 찾아서 토큰을 가져온다.
        // 쿠키가 존재하지 않거나 해당 쿠키가 없으면 token은 null 상태 유지
        if (token == null && request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("token".equals(cookie.getName())) {
                    token = cookie.getValue();
                    break;
                }
            }
        }

        // 3) 토큰이 존재하고, 토큰이 유효하면 인증 처리 수행
        if (token != null && jwtUtil.isTokenValid(token)) {
            // 토큰에서 사용자 이름 추출
            String username = jwtUtil.getUsername(token);

            // 사용자 이름으로 UserDetails 객체 조회
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // 인증 토큰 생성 (인증된 사용자 정보와 권한 포함)
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            // SecurityContext에 인증 토큰 저장 (이후 Spring Security가 인증된 사용자로 인식)
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }

        // 다음 필터로 요청 전달 (필터 체인 계속 진행)
        filterChain.doFilter(request, response);
    }
}


