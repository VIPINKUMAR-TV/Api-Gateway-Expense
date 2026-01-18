package com.expense.gateway.api_gateway.filter;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class AuthFilter implements GlobalFilter, Ordered {

    @Autowired
    private JwtUtil jwtUtil;

    private static final List<String> PUBLIC_ENDPOINTS = List.of(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/refresh"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();
        System.out.println("Gateway Request Path = " + path);

        // 1️⃣ Allow specific public endpoints
        for (String publicPath : PUBLIC_ENDPOINTS) {
        	if (path.startsWith(publicPath)) {
                return chain.filter(exchange);
            }
//            if (path.contains(publicPath)) {
//                return chain.filter(exchange);
//            }
        }

        // 2️⃣ Allow all /api/auth/** pattern (fallback)
        if (path.startsWith("/api/auth/")) {
            return chain.filter(exchange);
        }

        // 3️⃣ X-User-Id header allowed (debug)
        String existingUserId = exchange.getRequest().getHeaders().getFirst("X-User-Id");
        if (existingUserId != null && !existingUserId.isBlank()) {
            return chain.filter(exchange);
        }

        // 4️⃣ Check Authorization header
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader == null || authHeader.isBlank()) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // 5️⃣ Validate JWT token and extract userId
        Optional<String> maybeUserId = jwtUtil.extractUserIdFromBearer(authHeader);

        if (maybeUserId.isEmpty()) {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            byte[] bytes = "Invalid or missing JWT token / userId claim".getBytes(StandardCharsets.UTF_8);
            return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
        }

        String userId = maybeUserId.get();

        // 6️⃣ Add X-User-Id and forward
        ServerHttpRequest mutatedRequest = exchange.getRequest()
                .mutate()
                .header("X-User-Id", userId)
                .build();

        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(mutatedRequest)
                .build();

        return chain.filter(mutatedExchange);
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 10;
    }
}