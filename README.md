[1] 로그인 요청
↓
[2] AuthenticationManager -> UserDetailsService -> DB 조회
↓
[3] 비밀번호 확인 → 토큰 생성 → 쿠키에 JWT 저장
↓
[4] 이후 요청에 JWT 쿠키 자동 포함
↓
[5] JwtAuthFilter → 토큰 검증 → SecurityContext에 인증 등록
↓
[6] 인증 완료된 요청으로 컨트롤러 접근 허용