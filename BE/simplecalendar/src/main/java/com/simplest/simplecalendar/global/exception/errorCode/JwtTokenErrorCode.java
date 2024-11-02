package com.simplest.simplecalendar.global.exception.errorCode;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@RequiredArgsConstructor
@Getter
public enum JwtTokenErrorCode implements ErrorCode {
    DOES_NOT_EXIST_TOKEN(HttpStatus.UNAUTHORIZED, "JWT-001", "JWT 토큰이 존재하지 않습니다."),
    EXPIRED_TOKEN(HttpStatus.UNAUTHORIZED, "JWT-002", "만료된 JWT 토큰입니다"),
    EXPIRED_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "JWT-003", "만료된 리프레시 토큰입니다."),
    INVALID_TOKEN_SIGNATURE(HttpStatus.UNAUTHORIZED, "JWT-004", "JWT 토큰 서명이 잘못되었습니다."),
    UNSUPPORTED_TOKEN(HttpStatus.UNAUTHORIZED, "JWT-005", "JWT 토큰 포맷이 잘못되었습니다."),
    INVALID_TOKEN(HttpStatus.UNAUTHORIZED, "JWT-006", "유효하지 않은 JWT 토큰입니다."),
    ;
    
    private HttpStatus httpStatus;
    private String code;
    private String message;

    JwtTokenErrorCode(HttpStatus httpStatus, String code, String message) {
        this.httpStatus = httpStatus;
        this.code = code;
        this.message = message;
    }
}