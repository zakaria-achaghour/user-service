package com.zakaria.users.web;

import com.zakaria.users.DTO.requests.LoginRequest;
import com.zakaria.users.entities.AppUser;
import com.zakaria.users.services.AccountService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AuthController {
    private JwtEncoder jwtEncoder;

    private JwtDecoder jwtDecoder;
    private AuthenticationManager authenticationManager;
    private AccountService accountService;

    public AuthController(
            JwtEncoder jwtEncoder,
            JwtDecoder jwtDecoder,
            AuthenticationManager authenticationManager,
            AccountService accountService
    ) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.authenticationManager = authenticationManager;
        this.accountService = accountService;
    }
    @PostMapping("/token")
    public  ResponseEntity<Map<String, String>> jwtToken(String grantType, String username, String password, boolean withRefreshToken, String refreshToken) {
        String scope = null;
        String subject = null;
        if (grantType.equals("password")) {
            Authentication authentication = this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            subject = authentication.getName();
            scope = authentication.getAuthorities()
                    .stream().map(auth -> auth.getAuthority())
                    .collect(Collectors.joining(" "));
        } else if (grantType.equals("refreshToken")) {
            if(refreshToken == null) {
                return new ResponseEntity<>(Map.of("errorMessage","Refresh  Token is required"), HttpStatus.UNAUTHORIZED);
            }
            Jwt decodeJWT = null;
            try {
                decodeJWT = jwtDecoder.decode(refreshToken);
            } catch (JwtException e) {
                return new ResponseEntity<>(Map.of("errorMessage",e.getMessage()), HttpStatus.UNAUTHORIZED);
            }
           subject = decodeJWT.getSubject();
           AppUser user = accountService.loadUserByUsername(subject);
           scope =  user.getRoles().stream().map(r -> r.getName()).collect(Collectors.joining(" "));
        }
        Map<String, String> idToken = new HashMap<>();

        Instant instant = Instant.now();
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .subject(subject)
                .issuedAt(instant)
                .expiresAt(instant.plus(withRefreshToken ? 30 : 60, ChronoUnit.MINUTES))
                .issuer("security-service")
                .claim("scope", scope)
                .build();
        String jwtAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();

        idToken.put("access-token", jwtAccessToken);
        if (withRefreshToken) {
            JwtClaimsSet jwtClaimsSetRefresh = JwtClaimsSet.builder()
                    .subject(subject)
                    .issuedAt(instant)
                    .expiresAt(instant.plus(90, ChronoUnit.MINUTES))
                    .issuer("security-service")
                    .build();
            String jwtRefreshToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSetRefresh)).getTokenValue();
            idToken.put("refresh-token", jwtRefreshToken);
        }
        return new ResponseEntity<>(idToken,HttpStatus.OK);
    }

    @PostMapping("auth/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequest loginRequest) {
        Authentication authentication =  authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        Map<String, String> idToken=new HashMap<>();
        String scope = null;
        scope = authentication.getAuthorities()
                .stream().map(auth -> auth.getAuthority())
                .collect(Collectors.joining(" "));
        Instant instant=Instant.now();
        JwtClaimsSet jwtClaimsSet=JwtClaimsSet.builder()
                .subject(authentication.getName())
                .issuedAt(instant)
                .expiresAt(instant.plus(5, ChronoUnit.MINUTES))
                .issuer("security-service")
                .claim("scope",scope)
                .build();
        String jwtAccessToken=jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idToken.put("access-token",jwtAccessToken);
        return  ResponseEntity.ok(idToken);
    }
}
