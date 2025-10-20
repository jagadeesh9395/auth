package com.kjr.auth.controller;

import com.kjr.auth.dto.AuthenticationRequest;
import com.kjr.auth.dto.RegisterRequest;
import com.kjr.auth.model.User;
import com.kjr.auth.service.AuthenticationService;
import com.kjr.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.LocalDateTime;

@Controller
@RequestMapping("/")
@RequiredArgsConstructor
public class WebController {

    private final AuthenticationService authenticationService;
    private final UserService userService;

    @GetMapping
    public String home() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null && auth.isAuthenticated() && !auth.getName().equals("anonymousUser") 
                ? "redirect:/welcome" : "redirect:/login";
    }

    @GetMapping("/login")
    public String showLoginForm(Model model,
                              @RequestParam(name = "error", required = false) String error,
                              @RequestParam(name = "logout", required = false) String logout) {
        if (error != null) {
            model.addAttribute("error", true);
        }
        if (logout != null) {
            model.addAttribute("logout", true);
        }
        if (!model.containsAttribute("loginRequest")) {
            model.addAttribute("loginRequest", new AuthenticationRequest());
        }
        return "login";
    }

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        if (!model.containsAttribute("registerRequest")) {
            model.addAttribute("registerRequest", new RegisterRequest());
        }
        return "register";
    }

    @PostMapping("/login")
    public String loginUser(@Valid @ModelAttribute("loginRequest") AuthenticationRequest request,
                          BindingResult bindingResult,
                          RedirectAttributes redirectAttributes) {
        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute(
                    "org.springframework.validation.BindingResult.loginRequest",
                    bindingResult);
            redirectAttributes.addFlashAttribute("loginRequest", request);
            return "redirect:/login";
        }

        // The actual authentication is handled by Spring Security
        // This method is just for form validation and error handling
        return "redirect:/welcome";
    }

    @GetMapping("/welcome")
    public String welcome(Model model, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated() || authentication.getName().equals("anonymousUser")) {
            return "redirect:/login";
        }
        
        // Update last login time
        userService.updateLastLogin(authentication.getName());
        
        // Get user details
        User user = userService.getUserByUsername(authentication.getName());
        model.addAttribute("user", user);
        
        return "welcome";
    }

    @PostMapping("/register")
    public String registerUser(@Valid @ModelAttribute("registerRequest") RegisterRequest request,
                             BindingResult bindingResult,
                             RedirectAttributes redirectAttributes) {

        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute(
                    "org.springframework.validation.BindingResult.registerRequest",
                    bindingResult);
            redirectAttributes.addFlashAttribute("registerRequest", request);
            return "redirect:/register";
        }

        if (!request.getPassword().equals(request.getConfirmPassword())) {
            bindingResult.rejectValue("confirmPassword", "error.registerRequest", "Passwords do not match");
            redirectAttributes.addFlashAttribute(
                    "org.springframework.validation.BindingResult.registerRequest",
                    bindingResult);
            redirectAttributes.addFlashAttribute("registerRequest", request);
            return "redirect:/register";
        }

        try {
            authenticationService.register(request);
            redirectAttributes.addFlashAttribute("successMessage",
                    "Registration successful! Please log in with your credentials.");
            return "redirect:/login?registered";
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("errorMessage",
                    "Registration failed: " + e.getMessage());
            redirectAttributes.addFlashAttribute("registerRequest", request);
            return "redirect:/register";
        }
    }
}
