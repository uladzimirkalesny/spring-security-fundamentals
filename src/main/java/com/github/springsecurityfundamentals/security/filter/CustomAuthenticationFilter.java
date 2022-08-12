package com.github.springsecurityfundamentals.security.filter;

import com.github.springsecurityfundamentals.security.authentication.CustomAuthentication;
import com.github.springsecurityfundamentals.security.manager.CustomAuthenticationManager;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RequiredArgsConstructor

@Component
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    private final CustomAuthenticationManager customAuthenticationManager;
    private static final String KEY_HEADER = "key";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String key = String.valueOf(request.getHeader(KEY_HEADER));

        String[] retrieveCredentials = retrieveCredentials(request);
        String username = retrieveCredentials[0];
        String password = retrieveCredentials[1];

        CustomAuthentication customAuthentication = new CustomAuthentication(false, key, username, password);

        Authentication authenticate = customAuthenticationManager.authenticate(customAuthentication);
        if (authenticate.isAuthenticated()) {
            SecurityContextHolder.getContext().setAuthentication(authenticate);
            filterChain.doFilter(request, response);
        }
    }

    private String[] retrieveCredentials(HttpServletRequest request) {
        String authorizationHeader = String.valueOf(request.getHeader(HttpHeaders.AUTHORIZATION));

        authorizationHeader = authorizationHeader.trim();
        byte[] base64Token = authorizationHeader.substring(6).getBytes(StandardCharsets.UTF_8);
        byte[] decoded = Base64.getDecoder().decode(base64Token);
        String token = new String(decoded, StandardCharsets.UTF_8);

        return token.split(":");
    }

}
