package com.github.bsamartins.springboot.notifications.configuration;

import com.github.bsamartins.springboot.notifications.filter.JWTAuthorizationWebFilter;
import com.github.bsamartins.springboot.notifications.service.JwtAuthenticationService;
import com.github.bsamartins.springboot.notifications.service.ReactiveUserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

import static org.springframework.security.config.web.server.SecurityWebFiltersOrder.AUTHENTICATION;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class WebFluxSecurityConfig {

    @Bean
    public ReactiveUserDetailsService reactiveUserDetailsService() {
        return new ReactiveUserDetailsServiceImpl();
    }

    @Bean
    protected ReactiveAuthenticationManager authenticationManager() {
        UserDetailsRepositoryReactiveAuthenticationManager authenticationManager = new UserDetailsRepositoryReactiveAuthenticationManager(reactiveUserDetailsService());
        authenticationManager.setPasswordEncoder(passwordEncoder());
        return authenticationManager;
    }

    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http, JwtAuthenticationService jwtAuthenticationService) {
        return http
                // Demonstrate that method security works
                // Best practice to use both for defense in depth
                .addFilterAt(jwtAuthorizationWebFilter(jwtAuthenticationService), AUTHENTICATION)
                .csrf().disable().authorizeExchange()
                .pathMatchers("/", "/api/login").permitAll()
                .pathMatchers("/api/**").authenticated()
                .and().build();
    }


//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
////                    .addFilterBefore(new JWTAuthorizationFilter(this.authenticationManager, this.jwtAuthenticationService), UsernamePasswordAuthenticationFilter.class)
//                    .csrf().disable().authorizeRequests()
//                    .antMatchers("/").permitAll()
//                    .antMatchers("/api/login").permitAll()
//                    .antMatchers("/api/**").authenticated();
//    }

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService())
//            .passwordEncoder(passwordEncoder());
//    }

    @Bean
    public InitializerBean initializerBean() {
        return new InitializerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JWTAuthorizationWebFilter jwtAuthorizationWebFilter(JwtAuthenticationService jwtAuthenticationService) {
        return new JWTAuthorizationWebFilter(jwtAuthenticationService);
    }
}