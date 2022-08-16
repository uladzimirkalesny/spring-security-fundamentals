package com.github.springsecurityfundamentals.security.provider.impl;

import com.github.springsecurityfundamentals.security.authentication.CustomAuthentication;
import com.github.springsecurityfundamentals.security.provider.CustomAuthenticationProvider;
import com.github.springsecurityfundamentals.service.JpaUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor

@Order(2)
@Component
public class UsernameAndPasswordCustomAuthenticationProvider implements CustomAuthenticationProvider {

    private final JpaUserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomAuthentication customAuthentication = (CustomAuthentication) authentication;
        UserDetails userDetails = userDetailsService.loadUserByUsername(customAuthentication.getUsername());
        if (userDetails.getPassword().equals(customAuthentication.getPassword())) {
            if (customAuthentication.isAuthenticated()) {
                return customAuthentication;
            }
            return new CustomAuthentication(true, null, userDetails.getUsername(), userDetails.getPassword());
        }
        throw new BadCredentialsException("UsernameAndPasswordCustomAuthenticationProvider exception");
    }

}
