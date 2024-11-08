package com.simplest.simplecalendar.domain.user.controller;

import com.simplest.simplecalendar.domain.user.dto.request.LoginRequest;
import com.simplest.simplecalendar.domain.user.dto.request.ReissueTokenRequest;
import com.simplest.simplecalendar.domain.user.dto.request.SignupRequest;
import com.simplest.simplecalendar.domain.user.dto.response.TokenResponse;
import com.simplest.simplecalendar.domain.user.service.UserService;
import com.simplest.simplecalendar.global.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.antlr.v4.runtime.Token;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "User", description = "사용자 관련 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/user")
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    @Operation(summary = "회원가입", description = "사용자 이메일(email), 비밀번호(password), 닉네임(nickname)을 이용하여 회원가입을 합니다.")
    public ResponseEntity<ApiResponse<?>> signup(@Valid @RequestBody SignupRequest signupRequest) {
        userService.signup(signupRequest);
        return new ResponseEntity<>(ApiResponse.createSuccess(null, "회원가입에 성공하였습니다."), HttpStatus.CREATED);
    }

    @PostMapping("/login")
    @Operation(summary = "로그인", description = "사용자 이메일(email), 비밀번호(password)를 이용하여 로그인을 합니다.")
    public ResponseEntity<ApiResponse<TokenResponse>> login(@Valid @RequestBody LoginRequest loginRequest, HttpServletResponse httpServletResponse){
        TokenResponse response = userService.login(loginRequest, httpServletResponse);
        return new ResponseEntity<>(ApiResponse.createSuccess(response, "로그인에 성공하였습니다."), HttpStatus.OK);
    }

    @PostMapping("/reissue")
    @Operation(summary = "토큰 재발급", description = "만료된 액세스 토큰과 리프레시 토큰을 이용하여 토큰을 재발급합니다.")
    public ResponseEntity<ApiResponse<TokenResponse>> reissueToken(@Valid @RequestBody ReissueTokenRequest reissueTokenRequest, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        TokenResponse response = userService.reissueToken(reissueTokenRequest, httpServletRequest, httpServletResponse);
        return new ResponseEntity<>(ApiResponse.createSuccess(response, "토큰 재발급에 성공하였습니다."), HttpStatus.OK);
    }
}
