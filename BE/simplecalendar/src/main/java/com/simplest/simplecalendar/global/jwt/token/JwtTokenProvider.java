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

    private final JwtErrorResponseSender jwtErrorResponseSender;
    private static final String AUTHORITIES_KEY = "auth";


    @Value("${jwt.secret}")
    private String secret;
    @Value("#{${jwt.expired.access-token}}")
    private Integer ACCESS_TOKEN_EXPIRED_TIME;
    @Value("#{${jwt.expired.refresh-token}}")
    private Integer REFRESH_TOKEN_EXPIRED_TIME;

    private final String REFRESH_COOKIE_NAME = "refresh_token";

    private Key key;
    @Override
    public void afterPropertiesSet() throws Exception {
        //TokenProvider bean 생성 후 생성자로 주입받은 secret 값을 이용해 암호화 키 생성
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // Authentication 권한 정보를 담은 액세스 토큰 생성
    public String createAccessToken(Long id) {
        Date expiredAt = new Date((new Date()).getTime() + ACCESS_TOKEN_EXPIRED_TIME * 1000L);

        String token = Jwts.builder()
                .setSubject(String.valueOf(id))
                .claim(AUTHORITIES_KEY, "USER")
                .setExpiration(expiredAt)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        // 토큰 반환
        return token;
    }

    // Authentication 권한 정보를 담은 액세스 토큰 생성
    public String createRefreshToken(Long id, HttpServletResponse httpServletResponse) {
        Date expiredAt = new Date((new Date()).getTime() + REFRESH_TOKEN_EXPIRED_TIME * 1000L);

        String token = Jwts.builder()
                .setSubject(String.valueOf(id))
                .setExpiration(expiredAt)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        // 쿠키에 토큰 저장
        Cookie cookie = new Cookie(REFRESH_COOKIE_NAME, token);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
//        cookie.setSecure(true); // https 에서만 가능
        cookie.setMaxAge(REFRESH_TOKEN_EXPIRED_TIME);
        httpServletResponse.addCookie(cookie);

        // 토큰 반환
        return token;
    }

    // 토큰 유효성 검사
    public boolean validateToken(String token, HttpServletResponse response) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
            jwtErrorResponseSender.sendErrorResponse(response, JwtTokenErrorCode.INVALID_TOKEN_SIGNATURE);
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
            // jwt 토큰 만료 에러 발생.
            jwtErrorResponseSender.sendErrorResponse(response, JwtTokenErrorCode.EXPIRED_TOKEN);
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
            jwtErrorResponseSender.sendErrorResponse(response, JwtTokenErrorCode.UNSUPPORTED_TOKEN);
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
            jwtErrorResponseSender.sendErrorResponse(response, JwtTokenErrorCode.INVALID_TOKEN);
        }
        log.info("Failed validation token");
        return false;
    }

    // 토큰 권한 가져오기
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // authorities list 가져오기
        Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, null, authorities);
    }

    public Long getUserId(String token) {
        String id = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody().getSubject();

        return Long.parseLong(id);
    }

    public String resolveAccessToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public String resolveRefreshToken(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        Optional<Cookie> cookie = Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals(REFRESH_COOKIE_NAME))
                .findFirst();
        return cookie.map(Cookie::getValue).orElse(null);
    }

    public void cookieInitial(HttpServletResponse response) {
        // 쿠키에 토큰 저장
        Cookie cookie = new Cookie(REFRESH_COOKIE_NAME, null);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
//        cookie.setSecure(true); // https 에서만 가능
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }


}

