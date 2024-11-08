package com.simplest.simplecalendar.global.exception.errorCode;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;


@RequiredArgsConstructor
@Getter
public enum UserErrorCode implements ErrorCode {
    INVALID_LOGIN_USER_ID(HttpStatus.BAD_REQUEST, "USER-001", "유효하지 않은 로그인 사용자 ID입니다."),
    INVALID_USER_ID(HttpStatus.BAD_REQUEST, "USER-002", "유효하지 않은 사용자 ID입니다."),
    USER_DUPLICATED(HttpStatus.BAD_REQUEST, "USER-003", "이미 존재하는 사용자입니다."),
    USER_MISMATCH(HttpStatus.BAD_REQUEST, "USER-004", "사용자가 일치하지 않습니다."),
    PASSWORD_MISMATCH(HttpStatus.BAD_REQUEST, "USER-005", "비밀번호가 일치하지 않습니다."),
    EMAIL_DUPLICATED(HttpStatus.CONFLICT, "USER-006", "중복된 유저 이메일입니다."),
    LOGIN_FAIL(HttpStatus.BAD_REQUEST, "USER-007", "이메일 혹은 비밀번호가 틀렸습니다"),
    DEFAULT_LOGIN_USER(HttpStatus.BAD_REQUEST, "USER-008", "이메일 계정으로 회원가입한 회원입니다."),
    SOCIAL_LOGIN_USER(HttpStatus.BAD_REQUEST, "USER-009", "소셜 계정으로 회원가입한 회원입니다."),

    ;

    private HttpStatus httpStatus;
    private String code;
    private String message;

    UserErrorCode(HttpStatus httpStatus, String code, String message) {
        this.httpStatus = httpStatus;
        this.code = code;
        this.message = message;
    }
}
