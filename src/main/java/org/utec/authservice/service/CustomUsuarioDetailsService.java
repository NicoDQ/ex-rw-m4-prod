package org.utec.authservice.service;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.utec.authservice.dto.CustomUserDetails;
import org.utec.authservice.model.Usuario;
import org.utec.authservice.respository.UsuarioRepository;
import org.springframework.security.core.userdetails.User;

import java.util.List;

@Service
public class CustomUsuarioDetailsService implements UserDetailsService {
    @Autowired
    private UsuarioRepository usuarioRepository;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuario user = usuarioRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

        return CustomUserDetails.builder()
                .id(user.getId())
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole())))
                .build();
    }

    public boolean userExists(String username) {
        return usuarioRepository.findByUsername(username).isPresent();
    }

    public Usuario saveUser(Usuario user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return usuarioRepository.save(user);
    }

    @PostConstruct
    public void initUsers() {
        if(usuarioRepository.findAll().isEmpty()){
            // Crear usuario admin
            Usuario admin = new Usuario();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("admin123"));
            admin.setRole("ADMIN");
            usuarioRepository.save(admin);

            // Crear un usario normal
            Usuario user = new Usuario();
            user.setUsername("user");
            user.setPassword(passwordEncoder.encode("user123"));
            user.setRole("USER");
            usuarioRepository.save(user);
        }
    }
}
