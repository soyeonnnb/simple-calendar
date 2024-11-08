package com.simplest.simplecalendar.global.exception.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.validation.FieldError;

import java.util.Arrays;
import java.util.Objects;


// @Valid 어노테이션 사용하면서 에러 발생 시,
// 어느 필드에서 에러가 발생했는지 응답을 위함
@Getter
@Builder
@RequiredArgsConstructor
public class ValidationError {
    private final String field;
    private final String message;

    public static ValidationError of(final FieldError fieldError) {
        return ValidationError.builder()
                .field(fieldError.getField())
                .message(fieldError.getDefaultMessage())
                .build();
    }

    public static ValidationError of(final MessageSourceResolvable messageSourceResolvable) {
        Object[] arguments = Objects.requireNonNull(messageSourceResolvable.getArguments());
        String field = "";

        // arguments 배열에 여러 항목이 있을 수 있음, 첫 번째 항목을 처리
        if (arguments.length > 0) {
            Object argument = arguments[0];

            // argument가 MessageSourceResolvable인 경우
            if (argument instanceof MessageSourceResolvable) {
                MessageSourceResolvable innerResolvable = (MessageSourceResolvable) argument;
                // codes에서 적절한 field 값을 찾음
                field = Arrays.stream(innerResolvable.getCodes())
                        .filter(code -> code != null && !code.isEmpty())
                        .findFirst()
                        .map(code -> code.split("\\.")[1])
                        .orElse("unknownField");
            } else {
                // argument가 MessageSourceResolvable이 아닌 경우, 그냥 그대로 사용
                field = argument.toString();
            }
        }

        // 기본 메시지에서 오류 메시지(예: 이메일 형식이 아닙니다.)를 가져오기
        String message = messageSourceResolvable.getDefaultMessage();

        return ValidationError.builder()
                .field(field)  // "field"는 동적으로 추출
                .message(message)  // "이메일 형식이 아닙니다."와 같은 오류 메시지
                .build();
    }

}

