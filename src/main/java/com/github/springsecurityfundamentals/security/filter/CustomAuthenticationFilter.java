package com.github.springsecurityfundamentals.security.filter;

import com.github.springsecurityfundamentals.security.authentication.CustomAuthentication;
import com.github.springsecurityfundamentals.security.manager.CustomAuthenticationManager;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor

@Component
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    private final CustomAuthenticationManager customAuthenticationManager;
    private static final String KEY_HEADER = "key";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String key = String.valueOf(request.getHeader(KEY_HEADER));

        CustomAuthentication customAuthentication = new CustomAuthentication(false, key);

        Authentication authenticate = customAuthenticationManager.authenticate(customAuthentication);
        if (authenticate.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(authenticate);
            filterChain.doFilter(request, response);
        }
    }

}
