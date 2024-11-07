package com.simplest.simplecalendar.domain.user.repository;

import com.simplest.simplecalendar.domain.user.entity.RefreshToken;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends CrudRepository<RefreshToken, String> {
    Optional<RefreshToken> findByRefreshToken(String refreshToken);
    Optional<RefreshToken> findByAuthId(String authId);

    Boolean existsByRefreshToken(String refreshToken);
}
