package com.simplest.simplecalendar.domain.user.service;

import com.simplest.simplecalendar.domain.user.dto.request.LoginRequest;
import com.simplest.simplecalendar.domain.user.dto.request.SignupRequest;
import com.simplest.simplecalendar.domain.user.dto.response.LoginResponse;
import com.simplest.simplecalendar.domain.user.entity.LoginMethod;
import com.simplest.simplecalendar.domain.user.entity.RefreshToken;
import com.simplest.simplecalendar.domain.user.entity.User;
import com.simplest.simplecalendar.domain.user.repository.RefreshTokenRepository;
import com.simplest.simplecalendar.domain.user.repository.UserRepository;
import com.simplest.simplecalendar.global.exception.dto.RestApiException;
import com.simplest.simplecalendar.global.exception.errorCode.UserErrorCode;
import com.simplest.simplecalendar.global.jwt.token.JwtTokenProvider;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.TimeToLive;
import org.springframework.data.redis.core.index.Indexed;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Date;

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
        if (userRepository.existsByEmailAndMethod(signupRequest.getEmail(), LoginMethod.DEFAULT)) {
            throw new RestApiException(UserErrorCode.EMAIL_DUPLICATED, "[email="+signupRequest.getEmail()+"]");
        }

        User user = signupRequest.toEntity(passwordEncoder.encode(signupRequest.getPassword()));

        userRepository.save(user);
    }

    public LoginResponse login(LoginRequest loginRequest) {
        User user = userRepository.findByEmailAndMethod(loginRequest.getEmail(), LoginMethod.DEFAULT)
                .orElseThrow(() -> new RestApiException(UserErrorCode.LOGIN_FAIL, "[uid="+loginRequest.getEmail()+"]"));

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new RestApiException(UserErrorCode.PASSWORD_MISMATCH);
        }

        String accessToken = jwtTokenProvider.createAccessToken(user.getId());
        String refreshToken = jwtTokenProvider.createRefreshToken(user.getId());

        refreshTokenRepository.save(RefreshToken.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .expiredAt((new Date()).getTime() + REFRESH_TOKEN_EXPIRED_TIME)
                .build());

        return LoginResponse.of(accessToken, refreshToken);
    }

}
