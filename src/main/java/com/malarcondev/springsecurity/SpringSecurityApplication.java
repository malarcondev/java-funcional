package com.malarcondev.springsecurity;

import com.malarcondev.springsecurity.entity.Role;
import com.malarcondev.springsecurity.entity.RoleEntity;
import com.malarcondev.springsecurity.entity.UserEntity;
import com.malarcondev.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@SpringBootApplication
public class SpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    UserRepository userRepository;

    @Bean
    CommandLineRunner init(){
        return args -> {

            UserEntity userEntity = UserEntity.builder()
                    .email("santiago@mail.com")
                    .username("santiago")
                    .password(passwordEncoder.encode("1234"))
                    .roles(Set.of(RoleEntity.builder()
                            .name(Role.valueOf(Role.ADMIN.name()))
                            .build()))
                    .build();

            UserEntity userEntity2 = UserEntity.builder()
                    .email("anyi@mail.com")
                    .username("anyi")
                    .password(passwordEncoder.encode("1234"))
                    .roles(Set.of(RoleEntity.builder()
                            .name(Role.valueOf(Role.USER.name()))
                            .build()))
                    .build();

            UserEntity userEntity3 = UserEntity.builder()
                    .email("andrea@mail.com")
                    .username("andrea")
                    .password(passwordEncoder.encode("1234"))
                    .roles(Set.of(RoleEntity.builder()
                            .name(Role.valueOf(Role.INVITED.name()))
                            .build()))
                    .build();

            userRepository.save(userEntity);
            userRepository.save(userEntity2);
            userRepository.save(userEntity3);
        };
    }

}
