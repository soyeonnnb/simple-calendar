package com.simplest.simplecalendar.global.exception.errorCode;

import org.springframework.http.HttpStatus;

// ErrorCode의 추상 메서드
public interface ErrorCode {
    HttpStatus getHttpStatus();
    String getCode();
    String getMessage();
}
