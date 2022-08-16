package com.github.springsecurityfundamentals.security.provider;

import com.github.springsecurityfundamentals.security.authentication.CustomAuthentication;
import org.springframework.security.authentication.AuthenticationProvider;

public interface CustomAuthenticationProvider extends AuthenticationProvider {

    @Override
    default boolean supports(Class<?> authentication) {
        return CustomAuthentication.class.equals(authentication);
    }

}
