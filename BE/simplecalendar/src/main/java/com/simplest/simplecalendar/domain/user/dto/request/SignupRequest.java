package com.simplest.simplecalendar.domain.user.dto.request;

import com.simplest.simplecalendar.domain.user.entity.LoginMethod;
import com.simplest.simplecalendar.domain.user.entity.User;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import org.hibernate.validator.constraints.Length;

@Getter
public class SignupRequest {

    @Email(message = "이메일 형식이 아닙니다.")
    @NotBlank(message = "필수 영역입니다.")
    private String email;

    @NotBlank(message = "필수 영역입니다.")
    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[~!@#$%^&*()+|=])[A-Za-z\\d~!@#$%^&*()+|=]{8,16}$", message = "비밀번호는 8~16자 영문 대 소문자, 숫자, 특수문자를 사용하세요.")
    private String password;

    @NotBlank(message = "필수 영역입니다.")
    @Length(max = 40)
    private String nickname;

    public User toEntity(String password) {
        return User.builder()
                .email(this.email)
                .password(password)
                .nickname(this.nickname)
                .method(LoginMethod.DEFAULT)
                .build();
    }
}
