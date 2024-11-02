package com.simplest.simplecalendar.global.jwt.response;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.simplest.simplecalendar.global.dto.ApiResponse;
import com.simplest.simplecalendar.global.exception.errorCode.ErrorCode;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;

// 오류 응답을 전송
@Component
public class JwtErrorResponseSender {
    public static void sendErrorResponse(HttpServletResponse response, ErrorCode errorCode) {
        try {
            ApiResponse<Integer> errorResponse = ApiResponse.createError(
                    errorCode.getCode(), errorCode.getMessage());

            // json 형식으로 내보냄
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            response.setStatus(errorCode.getHttpStatus().value());

            // 에러 메세지 보내기
            new ObjectMapper().writeValue(response.getOutputStream(), errorResponse);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}