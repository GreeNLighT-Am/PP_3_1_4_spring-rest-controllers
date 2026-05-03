package com.greenlight.spring_boot_security.controllers;

import com.greenlight.spring_boot_security.models.Role;
import com.greenlight.spring_boot_security.models.User;
import com.greenlight.spring_boot_security.repositories.RoleRepository;
import com.greenlight.spring_boot_security.service.UserService;
import com.greenlight.spring_boot_security.validation.OnCreate;
import com.greenlight.spring_boot_security.validation.OnUpdate;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/admin")
public class AdminRestController {

    private final UserService userService;
    private final RoleRepository roleRepository;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.showAllUsers();
        return ResponseEntity.ok(users);
    }

    @GetMapping("/current-user")
    public ResponseEntity<User> getCurrentUser(Principal principal) {
        Optional<User> user = userService.findUserWithRolesByEmail(principal.getName());
        return user.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/roles")
    public ResponseEntity<List<Role>> getAllRoles() {
        List<Role> roles = roleRepository.findAll();
        return ResponseEntity.ok(roles);
    }

    @PostMapping("/users")
    public ResponseEntity<?> addUser(@RequestBody @Validated(OnCreate.class) User newUser,
                                     BindingResult bindingResult) {

        // Проверка уникальности email
        if (!userService.isEmailUnique(newUser.getEmail(), newUser.getId())) {
            bindingResult.rejectValue("email", "error.email", "Пользователь с таким email уже существует");
        }

        if (bindingResult.hasErrors()) {
            Map<String, String> errors = new HashMap<>();
            bindingResult.getFieldErrors().forEach(error ->
                    errors.put(error.getField(), error.getDefaultMessage())
            );
            return ResponseEntity.badRequest().body(errors);
        }

        // Обработка ролей
        if (newUser.getRoles() != null && !newUser.getRoles().isEmpty()) {
            List<Integer> roleIds = newUser.getRoles().stream()
                    .map(Role::getId)
                    .collect(Collectors.toList());
            List<Role> selectedRoles = roleRepository.findByIdIn(roleIds);
            newUser.setRoles(selectedRoles);
        } else {
            newUser.setRoles(Collections.emptyList());
        }

        userService.addUser(newUser);

        Map<String, Object> response = new HashMap<>();
        response.put("message", String.format("Пользователь c email %s успешно создан.", newUser.getEmail()));
        response.put("user", newUser);
        return ResponseEntity.ok().body(response);
    }

    @PutMapping("/users/{id}")
    public ResponseEntity<?> updateUser(@PathVariable Integer id,
                                        @RequestBody @Validated(OnUpdate.class) User user,
                                        BindingResult bindingResult) {

        user.setId(id);

        // Проверка уникальности email
        if (!userService.isEmailUnique(user.getEmail(), user.getId())) {
            bindingResult.rejectValue("email", "error.email", "Пользователь с таким email уже существует");
        }

        if (bindingResult.hasErrors()) {
            Map<String, String> errors = new HashMap<>();
            bindingResult.getFieldErrors().forEach(error ->
                    errors.put(error.getField(), error.getDefaultMessage())
            );
            return ResponseEntity.badRequest().body(errors);
        }

        // Обработка ролей
        if (user.getRoles() != null && !user.getRoles().isEmpty()) {
            List<Integer> roleIds = user.getRoles().stream()
                    .map(Role::getId)
                    .collect(Collectors.toList());
            List<Role> selectedRoles = roleRepository.findByIdIn(roleIds);
            user.setRoles(selectedRoles);
        } else {
            user.setRoles(Collections.emptyList());
        }

        userService.updateUser(user);

        Map<String, Object> response = new HashMap<>();
        response.put("message", String.format("Пользователь с email %s успешно отредактирован.", user.getEmail()));
        response.put("user", user);
        return ResponseEntity.ok().body(response);
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Integer id) {
        Optional<User> userOpt = userService.findUserById(id);

        if (userOpt.isPresent()) {
            String userEmail = userOpt.get().getEmail();
            userService.deleteUserById(id);

            Map<String, String> response = new HashMap<>();
            response.put("message", String.format("Пользователь %s успешно удалён.", userEmail));
            return ResponseEntity.ok().body(response);
        } else {
            return ResponseEntity.notFound().build();
        }
    }
}