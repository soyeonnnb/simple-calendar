package com.simplest.simplecalendar.global.jwt.service;

import com.simplest.simplecalendar.global.exception.dto.RestApiException;
import com.simplest.simplecalendar.global.exception.errorCode.UserErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
@Slf4j
public class PrinicalDetailService implements UserDetailsService {

//    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
//        log.info("load user by username");
//        User user = userRepository.findById(Long.parseLong(userId)).orElseThrow(() -> new RestApiException(UserErrorCode.INVALID_USER_ID));
//        return createUser(user);
        return null;
    }

//    private org.springframework.security.core.userdetails.User createUser(User user) {
//        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(user.getType());
//        return new org.springframework.security.core.userdetails.User(
//                user.getId().toString(),
//                "",
//                Collections.singletonList(grantedAuthority)
//        );
//    }
}
