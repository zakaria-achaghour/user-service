package com.zakaria.users.repositories;

import com.zakaria.users.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole, String> {
    AppRole findByName(String name);
}
