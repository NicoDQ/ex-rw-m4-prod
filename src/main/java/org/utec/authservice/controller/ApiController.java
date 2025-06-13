package org.utec.authservice.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ApiController {
    @GetMapping("/public/hello")
    public ResponseEntity<String> publicHello() {
        return ResponseEntity.ok("Hola mundo publico");
    }
    @Operation(summary = "Admin Data", security = @SecurityRequirement(name = "bearerAuth"))
    @GetMapping("/admin/data")
    public ResponseEntity<String> adminData () {
        return ResponseEntity.ok("Este es un dato secreto para los admins");
    }
}
