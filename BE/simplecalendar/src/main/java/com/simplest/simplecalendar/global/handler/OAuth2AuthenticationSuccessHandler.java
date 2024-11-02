package com.simplest.simplecalendar.global.handler;

import com.simplest.simplecalendar.global.jwt.token.JwtTokenProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;


@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private final JwtTokenProvider tokenProvider;

    @Value("${server.host.front}")
    private String hostAddress;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.info("social login success");
        log.info("social login authentication: {}", authentication);

//        tokenProvider.createTokens(Long.parseLong(authentication.getName()), authentication.getAuthorities().stream().findFirst().orElse(null).toString(), response);

        // OAuth2AuthenticationToken으로 캐스팅
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;

        // OAuth2User 가져오기
        OAuth2User oauthUser = (OAuth2User) oauthToken.getPrincipal();

        // 사용자 속성 가져오기
        Map<String, Object> userAttributes = oauthUser.getAttributes();
        StringBuilder sb = new StringBuilder();
        sb.append(hostAddress).append("/social-login-success");

        redirectStrategy.sendRedirect(request, response, sb.toString());
    }

}
