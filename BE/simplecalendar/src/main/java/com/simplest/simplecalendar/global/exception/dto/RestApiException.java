package com.simplest.simplecalendar.global.exception.dto;

import com.simplest.simplecalendar.global.exception.errorCode.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class RestApiException extends RuntimeException{
    private final ErrorCode errorCode;
    private String log;

    public RestApiException(ErrorCode errorCode, String log) {
        this.errorCode = errorCode;
        this.log = log;
    }
}
