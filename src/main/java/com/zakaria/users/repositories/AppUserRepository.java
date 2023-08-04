package com.zakaria.users.repositories;

import com.zakaria.users.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, String> {
    AppUser findByUsername(String username);
    AppUser findByEmail(String email);
}
