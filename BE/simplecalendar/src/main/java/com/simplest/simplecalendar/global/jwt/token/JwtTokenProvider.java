package com.simplest.simplecalendar.global.jwt.token;

import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.simplest.simplecalendar.global.exception.dto.RestApiException;
import com.simplest.simplecalendar.global.exception.errorCode.JwtTokenErrorCode;
import com.simplest.simplecalendar.global.exception.errorCode.UserErrorCode;
import com.simplest.simplecalendar.global.jwt.response.JwtErrorResponseSender;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider implements InitializingBean {

    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtErrorResponseSender jwtErrorResponseSender;
//    private final UserRepository userRepository;

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String AUTHORITIES_KEY = "auth";
    private static final String BEARER_TYPE = "Bearer";
    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";

    @Value("${jwt.secret}")
    private String secret;
    @Value("#{${jwt.expired.access-token}}")
    private Integer ACCESS_TOKEN_EXPIRED_TIME;
    @Value("#{${jwt.expired.refresh-token}}")
    private Integer REFRESH_TOKEN_EXPIRED_TIME;

    private Key key;

//    private final RefreshTokenRepository refreshTokenRepository;


    @Override
    public void afterPropertiesSet() throws Exception {
        //TokenProvider bean 생성 후 생성자로 주입받은 secret 값을 이용해 암호화 키 생성
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

//    // 토큰 생성
//    @Transactional
//    public String[] createTokens(Long id, String authority, HttpServletResponse response) {
//        long now = (new Date()).getTime();
//        String accessToken = createAccessToken(id, authority, now);
//        String refreshToken = createRefreshToken(id, now);
//        tokenSave(response, accessToken, refreshToken, now);
//        String[] result = new String[]{accessToken, refreshToken};
//        return result;
//    }
//
//    // ACCESS TOKEN 관련
//
//    // Authentication 권한 정보를 담은 액세스 토큰 생성
//    public String createAccessToken(Long id, String authority, Long now) {
//
//        Date expiredAt = new Date(now + ACCESS_TOKEN_EXPIRED_TIME * 1000L);
//
//        String accessToken = Jwts.builder()
//                .setSubject(String.valueOf(id))
//                .claim(AUTHORITIES_KEY, authority)
//                .setExpiration(expiredAt)
//                .signWith(key, SignatureAlgorithm.HS256)
//                .compact();
//
//        // 토큰 반환
//        return accessToken;
//    }
//
//    // Authentication 권한 정보를 담은 리프레시 토큰 생성
//    public String createRefreshToken(Long id, Long now) {
//        Date expiredAt = new Date(now + REFRESH_TOKEN_EXPIRED_TIME * 1000L);
//
//        String refreshToken = Jwts.builder()
//                .setSubject(String.valueOf(id))
//                .setExpiration(expiredAt)
//                .signWith(key, SignatureAlgorithm.HS256)
//                .compact();
//
//        // 토큰 저장
//        return refreshToken;
//    }
//
//
//    // token 저장
//    private void tokenSave(HttpServletResponse response, String accessToken, String refreshToken, Long now) {
//        // 토큰 저장
//        tokenCookieSave(response, accessToken, TYPE_ACCESS);
//        tokenCookieSave(response, refreshToken, TYPE_REFRESH); // 쿠키에 저장 -> 클라이언트에게 감
//        refreshTokenRepository.save(
//                RefreshToken.builder()
//                        .accessToken(accessToken)
//                        .refreshToken(refreshToken)
//                        .expiredAt(new Date(now + REFRESH_TOKEN_EXPIRED_TIME))
//                        .build()
//        ); // 서버에 저장 -> 비교군
//    }
//
//    // -------------------
//
//    // 쿠키에 저장
//    private void tokenCookieSave(HttpServletResponse response, String token, String type) {
//        Cookie cookie = new Cookie(type, token);
//        cookie.setHttpOnly(true);
//        cookie.setSecure(true);
//        cookie.setMaxAge(REFRESH_TOKEN_EXPIRED_TIME); // 만료 시간 -> 초
//        cookie.setPath("/"); // 유효한 경로 설정
//        response.addCookie(cookie);
//    }
//
//    // token 쿠키에서 삭제
//    @Transactional
//    public void tokenRemove(HttpServletResponse response, String accessToken, String refreshToken) {
//        // 쿠키에서 삭제 -> 클라이언트에게 감
//        log.info("토큰 삭제");
//        tokenCookieRemove(response, TYPE_ACCESS);
//        tokenCookieRemove(response, TYPE_REFRESH);
//
//        Optional<RefreshToken> optionalRefreshToken = refreshTokenRepository.findByAccessTokenAndRefreshToken(accessToken, refreshToken);
//        if (optionalRefreshToken.isPresent()) refreshTokenRepository.delete(optionalRefreshToken.get());
//    }
//
//    // 쿠키에서 삭제
//    @Transactional
//    public void tokenCookieRemove(HttpServletResponse response, String type) {
//        Cookie cookie = new Cookie(type, null);
//        cookie.setMaxAge(0);
//        cookie.setPath("/");
//        response.addCookie(cookie);
//    }
//
//    // 토큰 유효성 검사
//    public boolean validateToken(String token, HttpServletResponse response) {
//        try {
//            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
//            return true;
//        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
//            log.info("잘못된 JWT 서명입니다.");
//            jwtErrorResponseSender.sendErrorResponse(response, JwtTokenErrorCode.INVALID_TOKEN_SIGNATURE);
//        } catch (ExpiredJwtException e) {
//            log.info("만료된 JWT 토큰입니다.");
//            // jwt 토큰 만료 에러 발생.
//            jwtErrorResponseSender.sendErrorResponse(response, JwtTokenErrorCode.EXPIRED_TOKEN);
//        } catch (UnsupportedJwtException e) {
//            log.info("지원되지 않는 JWT 토큰입니다.");
//            jwtErrorResponseSender.sendErrorResponse(response, JwtTokenErrorCode.UNSUPPORTED_TOKEN);
//        } catch (IllegalArgumentException e) {
//            log.info("JWT 토큰이 잘못되었습니다.");
//            jwtErrorResponseSender.sendErrorResponse(response, JwtTokenErrorCode.INVALID_TOKEN);
//        }
//        log.info("Failed validation token");
//        return false;
//    }
//
//    public Long getUserId(String token, HttpServletResponse response) {
//        if (!validateToken(token, response)) return null;
//        Claims claims = Jwts.parserBuilder()
//                .setSigningKey(key)
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//        return Long.parseLong(claims.getSubject());
//    }
//
//    public boolean checkExpiredToken(String token) {
//        Claims claims = Jwts.parserBuilder()
//                .setSigningKey(key)
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//
//        return claims.getExpiration().after(new Date());
//    }
//
//    // 토큰 권한 가져오기
//    public Authentication getAuthentication(String token) {
//        Claims claims = Jwts.parserBuilder()
//                .setSigningKey(key)
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//
//        // authorities list 가져오기
//        Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
//                .map(SimpleGrantedAuthority::new)
//                .collect(Collectors.toList());
//
//        User principal = new User(claims.getSubject(), "", authorities);
//        return new UsernamePasswordAuthenticationToken(principal, null, authorities);
//    }
//
//    // HttpServletRequest 쿠키에서
//    // key에 해당하는 토큰이 있다면 해당 값 반환
//    public String resolveToken(HttpServletRequest request, String keyValue) {
//        if (request.getCookies() == null) return null;
//        Optional<Cookie> cookie = Arrays.stream(request.getCookies())
//                .filter(c -> c.getName().equals(keyValue))
//                .findFirst();
//        if (cookie.isPresent()) return cookie.get().getValue();
//        else return null;
//    }
//
//    // 재발급
//
//    public String reissue(HttpServletResponse response, String accessToken, String refreshToken) {
//        // 토큰이 쿠키에 없으면 재로그인 요청
//        if (accessToken == null || refreshToken == null) {
//            tokenCookieRemove(response, "access");
//            tokenCookieRemove(response, "refresh");
//            throw new RestApiException(JwtTokenErrorCode.DOES_NOT_EXIST_TOKEN);
//        }
//        // db에 있는 값인지 확인한 후, db에 없으면 유효하지 않다고 판단 -> 재로그인 요청
//        if (!refreshTokenRepository.existsByAccessTokenAndRefreshToken(accessToken, refreshToken))
//            throw new RestApiException(JwtTokenErrorCode.INVALID_TOKEN);
//        com.restgram.domain.user.entity.User user = userRepository.findById(getUserId(refreshToken, response)).orElseThrow(() -> new RestApiException(UserErrorCode.INVALID_USER_ID));
//
//        // 존재한다면 우선 토큰 삭제
//        tokenRemove(response, accessToken, refreshToken);
//        String[] tokens = createTokens(user.getId(), user.getType(), response);
//        return tokens[0];
//    }
//
//    public boolean validateRefreshToken(String refreshToken) {
//        // 만료기한 확인
//        if (!checkExpiredToken(refreshToken)) return false;
//
//        // 이미 사용된 refresh token인지 확인
//        if (!refreshTokenRepository.existsByRefreshToken(refreshToken)) return false;
//
//        log.info("refresh token 확인 완료");
//        return true;
//    }
}

