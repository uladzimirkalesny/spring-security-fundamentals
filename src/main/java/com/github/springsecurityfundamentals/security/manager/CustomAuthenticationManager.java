package com.github.springsecurityfundamentals.security.manager;

import com.github.springsecurityfundamentals.security.provider.CustomAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.List;

@RequiredArgsConstructor

@Component
public class CustomAuthenticationManager implements AuthenticationManager {

    private final List<CustomAuthenticationProvider> customAuthenticationProviders;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        for (CustomAuthenticationProvider customAuthenticationProvider : customAuthenticationProviders) {
            if (customAuthenticationProvider.supports(authentication.getClass())) {
                authentication = customAuthenticationProvider.authenticate(authentication);
            }
        }
        return authentication;
    }

}
