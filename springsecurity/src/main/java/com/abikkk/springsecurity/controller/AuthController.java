package com.abikkk.springsecurity.controller;

import com.abikkk.springsecurity.dto.RegisterRequest;
import com.abikkk.springsecurity.model.Role;
import com.abikkk.springsecurity.model.User;
import com.abikkk.springsecurity.repository.RoleRepository;
import com.abikkk.springsecurity.repository.UserRepository;
import com.abikkk.springsecurity.security.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.Set;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    //Register newUser API
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request){
        //check if username already exists.
        if(userRepository.findByUsername(request.getUsername()).isPresent()){
            return ResponseEntity.badRequest().body("Username already exists.");
        }

        User newUser = new User();
        newUser.setUsername(request.getUsername());
        String encodedPassword = passwordEncoder.encode(request.getPassword());
        newUser.setPassword(encodedPassword);
        System.out.println("Encoded Password : " + encodedPassword);

        //get role names and add to role entity.
        Set<Role> roles = new HashSet<>();
        for (String roleName : request.getRoles()) {
            Role role = roleRepository.findByName(roleName)
                    .orElseThrow(() -> new RuntimeException("Role not found: " + roleName));
            roles.add(role);
        }
        //assign roles to the user.
        newUser.setRoles(roles);
        //save newUser in the DB.
        userRepository.save(newUser);
        return ResponseEntity.ok("User registered successfully.");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody User loginRequest){
        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
            //to assign JWT to the User if the credentials are matching.
            String token = jwtUtil.generateToken(loginRequest.getUsername());
            return ResponseEntity.ok(token);
        }catch(BadCredentialsException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Username or Password");
        }
    }
}
