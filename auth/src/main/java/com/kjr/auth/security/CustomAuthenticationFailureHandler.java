package com.kjr.auth.security;

import com.kjr.auth.model.User;
import com.kjr.auth.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                      HttpServletResponse response,
                                      AuthenticationException exception) throws IOException, ServletException {
        
        String accept = request.getHeader("accept");
        String errorMessage = "Invalid username or password";

        // Handle response based on content type
        if (accept != null && accept.contains("application/json")) {
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().print(
                String.format("{\"status\":\"error\", \"message\":\"%s\"}", errorMessage)
            );
            response.getWriter().flush();
        } else {
            super.setDefaultFailureUrl("/login?error=true");
            super.setUseForward(true);
            getRedirectStrategy().sendRedirect(request, response, "/login?error=true");
        }
    }
}
