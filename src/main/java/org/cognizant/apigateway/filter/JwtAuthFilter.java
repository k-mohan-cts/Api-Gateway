package org.cognizant.apigateway.filter;

import org.cognizant.apigateway.util.JwtUtil;
import jakarta.ws.rs.core.HttpHeaders;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import org.springframework.core.Ordered;

import java.util.List;

@Component
@Slf4j
public class JwtAuthFilter implements GlobalFilter, Ordered {

    @Autowired
    private JwtUtil jwtUtil;

    // Defined the exact endpoints that do not require a JWT
    private static final List<String> PUBLIC_ENDPOINTS = List.of(
            "/api/users/login",
            "/api/users/createUser",
            "/api/users/getUserIdByEmail",
            "/api/citizens/createCitizen",
                "/api/documents/upload",
                "/api/documents/getDocById/",
                "/api/documents/download/",
            "/api/documents/citizen/"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        log.info("Global filter processing request for path: {}", path);

        // Check if the current path is in our list of allowed public endpoints
        if (PUBLIC_ENDPOINTS.stream().anyMatch(publicPath -> path.equals(publicPath) || path.startsWith(publicPath))) {
            log.info("Public endpoint accessed, bypassing JWT: {}", path);
            return chain.filter(exchange);
        }

        // Retrieve Authorization header
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // Validate existence and format of the Authorization header
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Unauthorized access attempt: Missing or invalid header for path: {}", path);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Extract the token (removing "Bearer " prefix)
        String token = authHeader.substring(7);

        try {
            // Validate the token signature and expiration
            if (!jwtUtil.validateToken(token)) {
                log.warn("Unauthorized access attempt: Invalid JWT for path: {}", path);
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            // Extract claims for downstream microservices
            String username = jwtUtil.extractUsername(token);
            String role = jwtUtil.extractRole(token);

            log.info("JWT validated. User: {} | Role: {}", username, role);

            // Mutate the request to pass user info in headers
            ServerWebExchange mutatedExchange = exchange.mutate()
                    .request(exchange.getRequest().mutate()
                            .header("X-User-Name", username)
                            .header("X-User-Role", role)
                            .build())
                    .build();

            return chain.filter(mutatedExchange);

        } catch (Exception e) {
            log.error("JWT Processing Error for path {}: {}", path, e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    @Override
    public int getOrder() {
        // High priority: runs before most other filters
        return -1;
    }
}