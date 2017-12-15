package com.github.bsamartins.springboot.notifications.configuration;

import com.github.bsamartins.springboot.notifications.filter.JWTAuthorizationFilter;
import com.github.bsamartins.springboot.notifications.filter.JWTAuthorizationWebFilter;
import com.github.bsamartins.springboot.notifications.service.JwtAuthenticationService;
import com.github.bsamartins.springboot.notifications.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//@Configuration
//@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtAuthenticationService jwtAuthenticationService;

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsServiceImpl();
    }

    @Bean
    @Override
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                    .addFilterBefore(new JWTAuthorizationFilter(this.authenticationManager(), this.jwtAuthenticationService), UsernamePasswordAuthenticationFilter.class)
                    .csrf().disable().authorizeRequests()
                    .antMatchers("/").permitAll()
                    .antMatchers("/api/login").permitAll()
                    .antMatchers("/api/**").authenticated();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService())
            .passwordEncoder(passwordEncoder());
    }

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