package com.simplest.simplecalendar.domain.user.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class ReissueTokenRequest {
    @NotBlank(message = "필수 영역입니다.")
    @Schema(description = "액세스 토큰")
    private String accessToken;
}
