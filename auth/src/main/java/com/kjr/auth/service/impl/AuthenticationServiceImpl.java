package com.kjr.auth.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kjr.auth.dto.AuthenticationRequest;
import com.kjr.auth.dto.AuthenticationResponse;
import com.kjr.auth.dto.RegisterRequest;
import com.kjr.auth.model.Role;
import com.kjr.auth.model.User;
import com.kjr.auth.repository.UserRepository;
import java.time.LocalDateTime;
import com.kjr.auth.security.JwtService;
import com.kjr.auth.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Override
    public AuthenticationResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already in use");
        }

        var user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)  // Changed from ADMIN to USER
                .enabled(true)
                .accountNonLocked(true)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .createdAt(LocalDateTime.now())
                .lastLogin(LocalDateTime.now())
                .build();

        userRepository.save(user);

        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("role", user.getRole());

        var jwtToken = jwtService.generateToken(extraClaims, user);
        var refreshToken = jwtService.generateRefreshToken(user);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .email(user.getEmail())
                .role(user.getRole())
                .build();
    }

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // First check if user exists and is locked
        var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Invalid username or password"));

        if (!user.isEnabled()) {
            throw new RuntimeException("Account is not activated. Please check your email to activate your account.");
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        if (authentication.isAuthenticated()) {
            // Update last login time
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);

            Map<String, Object> extraClaims = new HashMap<>();
            extraClaims.put("role", user.getRole());

            var jwtToken = jwtService.generateToken(extraClaims, user);
            var refreshToken = jwtService.generateRefreshToken(user);

            return AuthenticationResponse.builder()
                    .accessToken(jwtToken)
                    .refreshToken(refreshToken)
                    .email(user.getEmail())
                    .role(user.getRole())
                    .build();


        }else {
             throw new RuntimeException("Invalid username or password");
        }

    }
        @Override
        public void refreshToken (HttpServletRequest request, HttpServletResponse response) throws IOException {
            final String authHeader = request.getHeader("Authorization");
            final String refreshToken;
            final String userName;

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing or invalid Authorization header");
                return;
            }

            refreshToken = authHeader.substring(7);
            userName = jwtService.extractUsername(refreshToken);

            if (userName != null) {
                var user = this.userRepository.findByUsername(userName)
                        .orElseThrow(() -> new RuntimeException("User not found"));

                if (jwtService.isTokenValid(refreshToken, user)) {
                    Map<String, Object> extraClaims = new HashMap<>();
                    extraClaims.put("role", user.getRole());

                    var accessToken = jwtService.generateToken(extraClaims, user);
                    var newRefreshToken = jwtService.generateRefreshToken(user);

                    var authResponse = AuthenticationResponse.builder()
                            .accessToken(accessToken)
                            .refreshToken(newRefreshToken)
                            .build();

                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
                } else {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid refresh token");
                }
            } else {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid refresh token");
            }
        }
    }

