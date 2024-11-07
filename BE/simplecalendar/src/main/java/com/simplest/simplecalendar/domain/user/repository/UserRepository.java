package com.simplest.simplecalendar.domain.user.repository;

import com.simplest.simplecalendar.domain.user.entity.LoginMethod;
import com.simplest.simplecalendar.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmailAndMethod(String email, LoginMethod method);
    boolean existsByEmailAndMethod(String email, LoginMethod method);
}
