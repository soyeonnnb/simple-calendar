package com.simplest.simplecalendar.domain.user.service;

import com.simplest.simplecalendar.domain.user.dto.request.LoginRequest;
import com.simplest.simplecalendar.domain.user.dto.request.ReissueTokenRequest;
import com.simplest.simplecalendar.domain.user.dto.request.SignupRequest;
import com.simplest.simplecalendar.domain.user.dto.response.DuplicateCheckResponse;
import com.simplest.simplecalendar.domain.user.dto.response.TokenResponse;
import com.simplest.simplecalendar.domain.user.entity.LoginMethod;
import com.simplest.simplecalendar.domain.user.entity.RefreshToken;
import com.simplest.simplecalendar.domain.user.entity.User;
import com.simplest.simplecalendar.domain.user.repository.RefreshTokenRepository;
import com.simplest.simplecalendar.domain.user.repository.UserRepository;
import com.simplest.simplecalendar.global.exception.dto.RestApiException;
import com.simplest.simplecalendar.global.exception.errorCode.JwtTokenErrorCode;
import com.simplest.simplecalendar.global.exception.errorCode.UserErrorCode;
import com.simplest.simplecalendar.global.jwt.token.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("#{${jwt.expired.refresh-token}}")
    private Integer REFRESH_TOKEN_EXPIRED_TIME;

    @Transactional
    public void signup(SignupRequest signupRequest) {
        Optional<User> optionalUser = userRepository.findByEmail(signupRequest.getEmail());

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            if (user.getMethod().equals(LoginMethod.DEFAULT)) {
                throw new RestApiException(UserErrorCode.DEFAULT_LOGIN_USER, "[email="+signupRequest.getEmail()+"]");
            } else {
                throw new RestApiException(UserErrorCode.SOCIAL_LOGIN_USER, "[email="+signupRequest.getEmail()+"]");
            }
        }

        User user = signupRequest.toEntity(passwordEncoder.encode(signupRequest.getPassword()));

        userRepository.save(user);
    }

    @Transactional
    public TokenResponse login(LoginRequest loginRequest, HttpServletResponse httpServletResponse) {
        User user = userRepository.findByEmailAndMethod(loginRequest.getEmail(), LoginMethod.DEFAULT)
                .orElseThrow(() -> new RestApiException(UserErrorCode.LOGIN_FAIL, "[uid="+loginRequest.getEmail()+"]"));

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new RestApiException(UserErrorCode.PASSWORD_MISMATCH);
        }

        String accessToken = jwtTokenProvider.createAccessToken(user.getId());
        String refreshToken = jwtTokenProvider.createRefreshToken(user.getId(), httpServletResponse);

        refreshTokenRepository.save(RefreshToken.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .expiredAt((new Date()).getTime() + REFRESH_TOKEN_EXPIRED_TIME)
                .build());

        return TokenResponse.of(accessToken);
    }

    @Transactional
    public TokenResponse reissueToken(ReissueTokenRequest reissueTokenRequest, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        String resolveRefreshToken = jwtTokenProvider.resolveRefreshToken(httpServletRequest);
        Optional<RefreshToken> optionalRefreshToken = refreshTokenRepository.findByRefreshToken(resolveRefreshToken);
        if (optionalRefreshToken.isEmpty()) {
            jwtTokenProvider.cookieInitial(httpServletResponse);
            throw new RestApiException(JwtTokenErrorCode.EXPIRED_REFRESH_TOKEN);
        }

        RefreshToken refreshToken = optionalRefreshToken.get();
        if (!refreshToken.getAccessToken().equals(reissueTokenRequest.getAccessToken())) {
            jwtTokenProvider.cookieInitial(httpServletResponse);
            throw new RestApiException(JwtTokenErrorCode.ACCESS_TOKEN_AND_REFRESH_TOKEN_MISMATCH);
        }

        refreshTokenRepository.deleteById(refreshToken.getAuthId());

        Long id = jwtTokenProvider.getUserId(reissueTokenRequest.getAccessToken());

        String newAccessToken = jwtTokenProvider.createAccessToken(id);
        String newRefreshToken = jwtTokenProvider.createRefreshToken(id, httpServletResponse);

        refreshTokenRepository.save(RefreshToken.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .expiredAt((new Date()).getTime() + REFRESH_TOKEN_EXPIRED_TIME)
                .build());

        return TokenResponse.of(newAccessToken);
    }

    @Transactional(readOnly = true)
    public DuplicateCheckResponse checkDuplicateEmail(String email) {
        return DuplicateCheckResponse.of(userRepository.existsByEmailAndMethod(email, LoginMethod.DEFAULT));
    }
}
