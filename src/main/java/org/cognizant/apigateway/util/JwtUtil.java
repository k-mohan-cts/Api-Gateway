package org.cognizant.apigateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Component
public class JwtUtil {

    private static final String SECRET = "Y2Y4ZTM1YmYtYjYyMC00ZDllLTlhZTMtZDY2ZDU4ZTMxZmE5Cg";

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Generate JWT Token (Updated for 0.13.0)
    public String generateToken(String username, String role) {
        return Jwts.builder()
                .claim("role", role)
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hour
                .signWith(getSigningKey()) // Explicitly set the algorithm
                .compact();
    }

    // Extract username
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Extract role
    public String extractRole(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }

    // Extract expiration
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // Extract specific claim
    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        final Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    // Extract all claims (Updated for 0.13.0)
    private Claims extractAllClaims(String token) {
        return Jwts.parser() // parserBuilder() is now just parser()
                .verifyWith((SecretKey) getSigningKey()) // setSigningKey is replaced by verifyWith
                .build()
                .parseSignedClaims(token) // parseClaimsJws is now parseSignedClaims
                .getPayload(); // getBody() is now getPayload()
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Boolean validateToken(String token) {
        final String username = extractUsername(token);
        return  !isTokenExpired(token);
    }
}
