package com.zakaria.users.services;


import com.zakaria.users.entities.AppUser;
import lombok.AllArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private AccountService appAcocountService;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser =  appAcocountService.loadUserByUsername(username);
        if (appUser == null) throw new UsernameNotFoundException(String.format("User %s not found" , username));
        //String[] roles = appUser.getRoles().stream().map(r -> r.getName()).toArray(String[]::new);
        List<SimpleGrantedAuthority> authorities = appUser.getRoles().stream().map(r -> new SimpleGrantedAuthority(r.getName())).collect(Collectors.toList());
        UserDetails userDetails = User.withUsername(appUser.getUsername())
                .password(appUser.getPassword())
                .authorities(authorities)
                //      .roles(roles)
                .build();
        return userDetails;
    }
}
