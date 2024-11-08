package com.simplest.simplecalendar.domain.user.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Schema(defaultValue = "토큰 발급 응답 DTO")
public class TokenResponse {
    @Schema(description = "액세스 JWT TOKEN")
    private String accessToken;

    public static TokenResponse of(String accessToken) {
        return TokenResponse.builder()
                .accessToken(accessToken)
                .build();
    }
}
