package com.simplest.simplecalendar.domain.user.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;

@Getter
@Schema(description = "로그인 요청 DTO")
public class LoginRequest {
    @Email(message = "이메일 형식이 아닙니다.")
    @NotBlank(message = "필수 영역입니다.")
    @Schema(description = "이메일", defaultValue = "la28s5d@naver.com")
    private String email;

    @NotBlank(message = "필수 영역입니다.")
    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[~!@#$%^&*()+|=])[A-Za-z\\d~!@#$%^&*()+|=]{8,16}$", message = "비밀번호는 8~16자 영문 대 소문자, 숫자, 특수문자를 사용하세요.")
    @Schema(description = "비밀번호", defaultValue = "soyeon1234!")
    private String password;
}
