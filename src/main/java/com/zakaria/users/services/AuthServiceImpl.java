package com.zakaria.users.services;

import com.zakaria.users.entities.AppRole;
import com.zakaria.users.entities.AppUser;
import com.zakaria.users.repositories.AppRoleRepository;
import com.zakaria.users.repositories.AppUserRepository;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;
@Service
@Transactional
@AllArgsConstructor
@NoArgsConstructor
public class AuthServiceImpl implements AuthService {

    private AppUserRepository appUserRepository;
    private AppRoleRepository appRoleRepository;
    private PasswordEncoder passwordEncoder;
    @Override
    public AppUser addNewUser(String username, String password, String email, String confirmPassword) {

        AppUser appUser = appUserRepository.findByUsername(username);
        if (appUser != null) {
            throw new RuntimeException("this user already exist");
        }

        if (!password.equals(confirmPassword)) {
            throw new RuntimeException("password not match confirmed password");
        }

        AppUser user = AppUser.builder()
                .userId(UUID.randomUUID().toString())
                .username(username)
                .password(passwordEncoder.encode(password))
                .email(email)
                .build();
        appUserRepository.save(user);

        return user;
    }

    @Override
    public AppRole addNewRole(String name) {
        AppRole role = appRoleRepository.findByName(name);
        if (role != null) throw new RuntimeException("role already exist");

        return appRoleRepository.save(AppRole.builder().id(UUID.randomUUID().toString()).name(name).build());
    }

    @Override
    public void attachRoleToUser(String userName, String role) {
        AppUser appUser = appUserRepository.findByUsername(userName);
        AppRole appRole = appRoleRepository.findByName(role);
        appUser.getRoles().add(appRole);
    }

    @Override
    public void dettachRoleFromuser(String userName, String role) {
        AppUser appUser = appUserRepository.findByUsername(userName);
        AppRole appRole = appRoleRepository.findByName(role);
        appUser.getRoles().remove(appRole);
    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserRepository.findByUsername(username);
    }
}
