package com.simplest.simplecalendar.domain.user.controller;

import com.simplest.simplecalendar.domain.user.dto.request.LoginRequest;
import com.simplest.simplecalendar.domain.user.dto.request.SignupRequest;
import com.simplest.simplecalendar.domain.user.dto.response.LoginResponse;
import com.simplest.simplecalendar.domain.user.service.UserService;
import com.simplest.simplecalendar.global.dto.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/user")
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupRequest signupRequest) {
        userService.signup(signupRequest);
        return new ResponseEntity<>(ApiResponse.createSuccess(null, "회원가입에 성공하였습니다."), HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest){
        LoginResponse response = userService.login(loginRequest);
        return new ResponseEntity<>(ApiResponse.createSuccess(response, "로그인에 성공하였습니다."), HttpStatus.OK);
    }

}
