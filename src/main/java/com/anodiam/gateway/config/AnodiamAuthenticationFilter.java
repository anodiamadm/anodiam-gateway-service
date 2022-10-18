package com.anodiam.gateway.config;

import com.anodiam.security.AnodiamAuthentication;
import com.anodiam.security.AnodiamJwtDecoder;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public class AnodiamAuthenticationFilter implements WebFilter {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        try {
            HttpHeaders headers = exchange.getRequest().getHeaders();
            if (headers.containsKey("Authorization")) {
                if (headers.get("Authorization").get(0).startsWith("Bearer ")) {
                    final String token = headers.get("Authorization").get(0).replaceFirst("Bearer ", "");
                    JwtDecoder jwtDecoder = new AnodiamJwtDecoder();
                    Jwt jwt = jwtDecoder.decode(token);
                    Authentication authentication = new AnodiamAuthentication(jwt);
                    return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
                }
            }
        } catch (Exception e) {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }
        return chain.filter(exchange);
    }
}
