package org.utec.authservice.config.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import io.jsonwebtoken.Jwts;
import org.utec.authservice.dto.CustomUserDetails;

@Component
public class JwtTokenUtil {
//    private final Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    @Value("${jwt.secret}")
    private String secretkey;
    @Value("${jwt.expiration-time}")
//    private static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60; // 5 HORAS
    private long JWT_TOKEN_VALIDITY;

    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(secretkey.getBytes());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claim = new HashMap<>();
//        claim.put("roles", userDetails.getAuthorities().stream()
//                .map(authority -> authority.getAuthority())
//                .toList());

        if (userDetails instanceof CustomUserDetails customUser) {
            claim.put("userId", customUser.getId());
        }

        return Jwts.builder()
                .setClaims(claim)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
}
