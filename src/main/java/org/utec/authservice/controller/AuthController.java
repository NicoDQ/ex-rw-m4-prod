package org.utec.authservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.utec.authservice.config.jwt.JwtTokenUtil;
import org.utec.authservice.dto.AuthResponse;
import org.utec.authservice.model.AuthRequest;
import org.utec.authservice.model.Usuario;
import org.utec.authservice.service.CustomUsuarioDetailsService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    protected AuthenticationManager authenticationManager;
    @Autowired
    private CustomUsuarioDetailsService customUsuarioDetailsService;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthRequest authRequest) throws Exception {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );
        } catch (Exception e) {
            throw new Exception("Incorrect username or password", e);
        }

        final UserDetails userDetails = customUsuarioDetailsService.loadUserByUsername(authRequest.getUsername());
        final String jwt = jwtTokenUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AuthResponse(jwt));
    }


    @PostMapping("/registerUser")
    public ResponseEntity<String> registerUser(@RequestBody AuthRequest authRequest) {
        try {

            if (customUsuarioDetailsService.userExists(authRequest.getUsername())) {
                return ResponseEntity.ok()
                        .body("Username already exists");
            }

            Usuario newUser = new Usuario();
            newUser.setUsername(authRequest.getUsername());
            newUser.setPassword(authRequest.getPassword());
            newUser.setRole("USER"); // Role default
            // Save the user
            customUsuarioDetailsService.saveUser(newUser);

            return ResponseEntity.ok()
                    .body("User registered successfully");

        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Error during registration: " + e.getMessage());
        }
    }


    @PostMapping("/registerAdmin")
    public ResponseEntity<String> registerAdmin(@RequestBody AuthRequest authRequest) {
        try {

            if (customUsuarioDetailsService.userExists(authRequest.getUsername())) {
                return ResponseEntity.ok()
                        .body("Username already exists");
            }

            Usuario newUser = new Usuario();
            newUser.setUsername(authRequest.getUsername());
            newUser.setPassword(authRequest.getPassword());
            newUser.setRole("ADMIN"); // Role default
            // Save the user
            customUsuarioDetailsService.saveUser(newUser);

            return ResponseEntity.ok()
                    .body("User admin registered successfully");

        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Error during registration: " + e.getMessage());
        }
    }
}
