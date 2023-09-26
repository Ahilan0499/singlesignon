package com.javatechie.google.auth;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@SpringBootApplication
@RestController
public class SpringSsoGoogleApplication {

    @GetMapping("/")
    public String welcome() {
        return "index";
    }

    @GetMapping("/user")
    public Principal user(Principal principal) {
        System.out.println("username : " + principal.getName());
        return principal;
    }

    @GetMapping("/api")
    public String home(@AuthenticationPrincipal KeycloakAuthenticationToken principal, Model model){
        System.out.println(principal.getDetails());
        SimpleKeycloakAccount account = (SimpleKeycloakAccount) principal.getDetails();
        boolean isAdmin = account.getKeycloakSecurityContext().getToken().getRealmAccess().isUserInRole("admin");
        boolean isUser = account.getKeycloakSecurityContext().getToken().getRealmAccess().isUserInRole("user");
        if(isAdmin)
            return "Hey Admin!";
        else  if(isUser)
            return "Hey User!" + account.getKeycloakSecurityContext().getIdToken().getEmail();
        return "Login please";
    }


    public static void main(String[] args) {
        SpringApplication.run(SpringSsoGoogleApplication.class, args);
    }

}
