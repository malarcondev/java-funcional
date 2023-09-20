package com.malarcondev.springsecurity.controller;

import com.malarcondev.springsecurity.controller.request.UserDTO;
import com.malarcondev.springsecurity.entity.Role;
import com.malarcondev.springsecurity.entity.RoleEntity;
import com.malarcondev.springsecurity.entity.UserEntity;
import com.malarcondev.springsecurity.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
@AllArgsConstructor
//@RequestMapping("api/v1/auth")
public class AuthController {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    @GetMapping("/hello")
    public String hello(){
        return "helo world, not security";
    }

    @GetMapping("/hello-security")
    @PreAuthorize("hasRole('ADMIN') or hasRole('INVITED')")
    public String helloSecurity(){
        return "helo world, with security";
    }

    @PostMapping("/create")
    public ResponseEntity<?> createUser(@Valid @RequestBody UserDTO userDTO){

        Set<RoleEntity> roles = userDTO.getRoles().stream()
                .map(role -> RoleEntity.builder()
                        .name(Role.valueOf(role))
                        .build())
                .collect(Collectors.toSet());

        UserEntity userEntity = UserEntity.builder()
                .username(userDTO.getUsername())
                .password(passwordEncoder.encode(userDTO.getPassword()))
                .email(userDTO.getEmail())
                .roles(roles)
                .build();

        userRepository.save(userEntity);
        return ResponseEntity.ok(userEntity);
    }

    @DeleteMapping("/delete")
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(@RequestParam String id){
        userRepository.deleteById(Long.parseLong(id));
    }
}
