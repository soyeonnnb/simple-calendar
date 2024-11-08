package com.simplest.simplecalendar.global.jwt.filter;

import com.simplest.simplecalendar.global.exception.errorCode.JwtTokenErrorCode;
import com.simplest.simplecalendar.global.jwt.response.JwtErrorResponseSender;
import com.simplest.simplecalendar.global.jwt.token.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final JwtErrorResponseSender jwtErrorResponseSender;
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_TYPE = "Bearer";

    private final List<String> whiteList = List.of(
            "/api/v1/user/login",
            "/api/v1/user/signup",
            "/api/v1/user/reissue",

            "/error",
            "/login",
            "/oauth2/**",

            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html",
            "/favicon.ico");

    @Override // 이 주소로 오는 건 토큰 없어도 됨.
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();

        AntPathMatcher antPathMatcher = new AntPathMatcher();

        for(String p : whiteList) {
            System.out.println(p+" "+path+" "+antPathMatcher.match(p, path));
            if(antPathMatcher.match(p, path)){
                return true;
            }
        }
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("Jwt Filter 진행 ..");
        String accessToken = jwtTokenProvider.resolveAccessToken(request);

        // 만약 토큰이 존재하면 SecurityContextHolder에 권한을 생성하여 삽입
        if (accessToken != null) {
            if (jwtTokenProvider.validateToken(accessToken, response)) {
                Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else return;
        } else {
            log.warn("JWT 토큰 없음");
//             토큰이 필요한 요청에서 토큰이 없다면 리턴
            jwtErrorResponseSender.sendErrorResponse(response, JwtTokenErrorCode.DOES_NOT_EXIST_TOKEN);
            return;
        }
        filterChain.doFilter(request, response);
    }

}