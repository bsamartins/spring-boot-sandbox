package com.github.bsamartins.springboot.notifications.filter;

import com.github.bsamartins.springboot.notifications.service.JwtAuthenticationService;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.List;

import static com.github.bsamartins.springboot.notifications.SecurityConstants.HEADER_STRING;
import static com.github.bsamartins.springboot.notifications.SecurityConstants.TOKEN_PREFIX;

public class JWTAuthorizationWebFilter implements WebFilter {

    private JwtAuthenticationService jwtAuthenticationService;

    public JWTAuthorizationWebFilter(JwtAuthenticationService jwtAuthenticationService) {
        this.jwtAuthenticationService = jwtAuthenticationService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return Mono.just(exchange.getRequest())
                .log()
                .map(req -> getToken(req.getHeaders()))
                .log()
                .map(this::getAuthentication)
                .log()
                .map(ua -> {
                    SecurityContextHolder.getContext().setAuthentication(ua);
                    return null;
                })
                .log()
                .then(chain.filter(exchange));
    }

    private Authentication getAuthentication(String token) {
        return jwtAuthenticationService.authenticate(token);
    }

    private String getToken(HttpHeaders headers) {
        List<String> authHeaders = headers.get(HEADER_STRING);
        return java.util.Optional.ofNullable(authHeaders)
                .filter(hds -> !hds.isEmpty())
                .map(hds -> hds.get(0))
                .filter(h -> h.startsWith(TOKEN_PREFIX))
                .orElse(null);
    }
}