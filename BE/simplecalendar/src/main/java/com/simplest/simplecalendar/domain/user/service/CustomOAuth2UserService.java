package com.simplest.simplecalendar.domain.user.service;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

  @Override
  @Transactional
  public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
    return null;
  }

//  private final CustomerRepository customerRepository;
//  private final CalendarRepository calendarRepository;
//  private final CalendarService calendarService;
//
//  @Override
//  @Transactional
//  public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
//    // 기본 OAuth2UserService 객체를 생성
//    OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
//
//    // OAuth2UserService를 사용하여 OAuth2User 정보를 가져온다
//    OAuth2User oAuth2User = delegate.loadUser(userRequest);
//
//    // 클라이언트 등록 ID(kakao)
//    String registrationId = userRequest.getClientRegistration().getRegistrationId();
//    log.info(registrationId + " 로그인 시도");
//
//    // OAuth2 로그인 진행 시 키가 되는 필드 값(PK)
//    String userNameAttributeName = "id";
//    // OAuth2UserService를 사용하여 가져온  OAuth2User정보를 OAuth2Attribute 객체를 만든다
//    OAuthAttributes attributes = OAuthAttributes.of(registrationId, userNameAttributeName,
//        oAuth2User.getAttributes());
//    // OAuth2UserRequest에서 accessToken을 가져옴
//    OAuth2AccessToken accessToken = userRequest.getAccessToken();
//
//    // 저장
//    Customer customer = save(attributes, accessToken.getTokenValue());
//
//    // 유저가 캘린더 관련 동의 체크했는지 확인
//
//    boolean calendarAgree = oAuth2User.getAuthorities().stream()
//        .map(GrantedAuthority::getAuthority)
//        .anyMatch("SCOPE_talk_calendar"::equals);
//
//    boolean emailAgree = oAuth2User.getAuthorities().stream()
//        .map(GrantedAuthority::getAuthority)
//        .anyMatch("SCOPE_account_email"::equals);
//
//    if (calendarAgree && !calendarRepository.existsByCustomer(customer)) {
//      calendarService.createCalendar(customer);
//    }
//
//    if (emailAgree && customer.getEmail() == null) {
//      customer.updateEmail(attributes.getEmail());
//    }
//
//    // 여기서 리턴해주는 값을 successHandler에서 authentication 객체에서 확인할 수 있음.
//    return new DefaultOAuth2User(
//        Collections.singleton(new SimpleGrantedAuthority(customer.getType()))
//        , toMap(customer)
//        , attributes.getNameAttributeKey());
//  }
//
//
//  private Customer save(OAuthAttributes attributes, String accessToken) {
//    Customer customer = customerRepository.findByUidAndLoginMethod(attributes.getUid(),
//            attributes.getLoginMethod())
//        // 우리 프로젝트에서는 유저의 닉네임/사진에 대한 실시간 정보가 필요 없기 때문에 update는 하지 않는다.
//        .orElse(attributes.toEntity());
//    customer.updateAccessToken(accessToken);
//    return customerRepository.save(customer);
//  }
//
//  private Map<String, Object> toMap(Customer customer) {
//    Map<String, Object> map = new TreeMap<>();
//    map.put("id", customer.getId());
//    map.put("uid", customer.getUid());
//    map.put("email", customer.getEmail());
//    map.put("name", customer.getName());
//    map.put("profileImage", customer.getProfileImage());
//    map.put("phone", customer.getPhone());
//    map.put("loginMethod", customer.getLoginMethod().getName());
//    return map;
//  }


}
