package com.github.springsecurityfundamentals.security.provider.impl;

import com.github.springsecurityfundamentals.security.authentication.CustomAuthentication;
import com.github.springsecurityfundamentals.security.provider.CustomAuthenticationProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Order(1)
@Component
public class KeyCustomAuthenticationProvider implements CustomAuthenticationProvider {

    @Value("${secret.key}")
    private String secretKey;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomAuthentication customAuthentication = (CustomAuthentication) authentication;
        String headerKey = customAuthentication.getKey();
        if (secretKey.equals(headerKey)) {
            return new CustomAuthentication(true, null, customAuthentication.getUsername(), customAuthentication.getPassword());
        }
        throw new BadCredentialsException("KeyCustomAuthenticationProvider exception");
    }

}
