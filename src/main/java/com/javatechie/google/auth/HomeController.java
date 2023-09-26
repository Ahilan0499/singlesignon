package com.javatechie.google.auth;
import org.keycloak.KeycloakPrincipal;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(@AuthenticationPrincipal KeycloakPrincipal principal, Model model) {
        if (principal != null) {
            if (principal.getKeycloakSecurityContext().getToken().getRealmAccess().isUserInRole("admin")) {
                model.addAttribute("message", "Hey Admin");
            } else if (principal.getKeycloakSecurityContext().getToken().getRealmAccess().isUserInRole("user")) {
                model.addAttribute("message", "Hey User");
            }
        } else {
            model.addAttribute("message", "Go and register first");
        }
        return "/api";
    }
}
