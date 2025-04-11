package com.abikkk.springsecurity.security;

import com.abikkk.springsecurity.model.Role;
import com.abikkk.springsecurity.model.User;
import com.abikkk.springsecurity.repository.UserRepository;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    //secret key
    private static final SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    private final int jwtExpirationMs = 86400000;

    private final UserRepository userRepository;

    public JwtUtil(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    //generate Token.
    public String generateToken(String username){
        Optional<User> user = userRepository.findByUsername(username);
        Set<Role> roles = user.get().getRoles();
        //add roles to the token.
        return Jwts.builder().setSubject(username).claim("roles", roles.stream()
                .map(role -> role.getName()).collect(Collectors.joining(",")))
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(secretKey)
                .compact();
    }
    //extract userName.
    public String extractUsername(String token){
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody().getSubject();
    }
    //extract roles.
    public Set<String> extractRoles(String token){
        String rolesString = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody().get("roles",String.class);
        return Set.of(rolesString);
    }
    //Token Validation.
    public boolean isTokenValid(String token){
        try{
            Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
            return true;
        }catch (JwtException | IllegalArgumentException e){
            return false;
        }
    }

}
