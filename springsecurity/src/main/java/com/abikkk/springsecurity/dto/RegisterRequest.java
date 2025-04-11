package com.abikkk.springsecurity.dto;

import com.abikkk.springsecurity.model.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    private String username;
    private String password;
    private Set<String> roles; // a set of role names to be passed in the request.
}
