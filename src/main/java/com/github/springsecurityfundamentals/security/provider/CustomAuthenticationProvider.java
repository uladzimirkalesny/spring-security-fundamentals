package com.github.springsecurityfundamentals.security.provider;

import com.github.springsecurityfundamentals.security.authentication.CustomAuthentication;
import com.github.springsecurityfundamentals.service.JpaUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Value("${secret.key}")
    private String secretKey;

    private final JpaUserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomAuthentication customAuthentication = (CustomAuthentication) authentication;

        String headerKey = customAuthentication.getKey();
        if (secretKey.equals(headerKey)) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(customAuthentication.getUsername());
            if (userDetails.getPassword().equals(customAuthentication.getPassword())) {
                return new CustomAuthentication(true, null, userDetails.getUsername(), userDetails.getPassword());
            }
        }

        throw new BadCredentialsException("CustomAuthenticationProvider Exception");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomAuthentication.class.equals(authentication);
    }

}
