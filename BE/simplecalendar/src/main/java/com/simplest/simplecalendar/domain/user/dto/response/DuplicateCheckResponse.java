package com.simplest.simplecalendar.domain.user.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Getter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Schema(defaultValue = "중복확인 DTO")
public class DuplicateCheckResponse {

    @Schema(description = "중복확인 결과 | true(중복) false(중복X)")
    private boolean check;

    public static DuplicateCheckResponse of(boolean check) {
        return DuplicateCheckResponse.builder()
                .check(check)
                .build();
    }
}
