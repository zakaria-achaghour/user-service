package com.zakaria.users.services;

import com.zakaria.users.entities.AppRole;
import com.zakaria.users.entities.AppUser;

public interface AuthService {

    AppUser addNewUser(String username, String password, String email, String confirmPassword);
    AppRole addNewRole(String role);

    void attachRoleToUser(String userName, String role);
    void dettachRoleFromuser(String userName, String role);

    AppUser loadUserByUsername(String username);
}
