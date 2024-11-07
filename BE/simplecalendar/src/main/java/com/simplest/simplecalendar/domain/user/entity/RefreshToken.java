package com.simplest.simplecalendar.domain.user.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;
import org.springframework.data.redis.core.index.Indexed;

@Builder
@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@RedisHash(value = "refresh_token")
public class RefreshToken {

    @Id
    private String authId; // id

    private String accessToken; // 액세스 토큰

    @Indexed
    private String refreshToken; // 리프레시 토큰

    @TimeToLive
    private long expiredAt; // 만료일


}