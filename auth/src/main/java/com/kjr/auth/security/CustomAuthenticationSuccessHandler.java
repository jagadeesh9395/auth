package com.kjr.auth.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, 
                                      HttpServletResponse response, 
                                      Authentication authentication) throws IOException, ServletException {
        
        String accept = request.getHeader("accept");
        
        // If it's an API request (e.g., Content-Type: application/json)
        if (accept != null && accept.contains("application/json")) {
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().print("{\"status\":\"success\", \"redirect\":\"/welcome\"}");
            response.getWriter().flush();
        } else {
            // For web requests, redirect to the welcome page
            getRedirectStrategy().sendRedirect(request, response, "/welcome");
        }
    }
}
