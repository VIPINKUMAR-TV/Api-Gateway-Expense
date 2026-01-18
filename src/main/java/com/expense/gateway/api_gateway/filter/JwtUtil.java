package com.expense.gateway.api_gateway.filter;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    /**
     * Build the signing key from the configured secret.
     * Uses the same approach as AuthService (interpret secret as plain text bytes).
     */
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Validate a raw JWT (token without "Bearer " prefix).
     * Returns true if valid, false otherwise.
     */
    public boolean validateToken(String token) {
        if (token == null || token.isBlank()) return false;
        try {
            Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            return false;
        }
    }

    /**
     * Accepts a header value that may start with "Bearer ", validates the token,
     * and returns the parsed Claims Jws if valid.
     */
    private Optional<Jws<Claims>> parseClaimsJwsFromBearer(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) return Optional.empty();
        String token = bearerToken.startsWith("Bearer ") ? bearerToken.substring(7) : bearerToken;
        try {
            Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            return Optional.of(claims);
        } catch (JwtException | IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    /**
     * Extract user id from a Bearer header (checks "userId", then "id", then subject).
     * Returns Optional.empty() if token is missing/invalid or claim not present.
     */
    public Optional<String> extractUserIdFromBearer(String bearerToken) {
        return parseClaimsJwsFromBearer(bearerToken)
                .map(jws -> {
                    Claims claims = jws.getBody();
                    if (claims.containsKey("userId")) {
                        return String.valueOf(claims.get("userId"));
                    }
                    if (claims.containsKey("id")) {
                        return String.valueOf(claims.get("id"));
                    }
                    String sub = claims.getSubject();
                    return (sub != null && !sub.isBlank()) ? sub : null;
                })
                .filter(s -> s != null && !s.isBlank());
    }
}
