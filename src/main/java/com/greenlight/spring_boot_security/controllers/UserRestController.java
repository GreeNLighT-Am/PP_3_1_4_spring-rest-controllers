package com.greenlight.spring_boot_security.controllers;

import com.greenlight.spring_boot_security.models.User;
import com.greenlight.spring_boot_security.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/user")
public class UserRestController {

    private final UserService userService;

    @GetMapping("/current")
    public ResponseEntity<User> getCurrentUser(Principal principal) {
        return userService.findUserWithRolesByEmail(principal.getName())
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}