package com.github.bsamartins.springboot.notifications.security;

import com.github.bsamartins.springboot.notifications.persistence.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import reactor.core.publisher.Mono;

import java.util.Collections;

public class ReactiveUserDetailsServiceImpl implements ReactiveUserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return userRepository.findByUsername(username)
                .map(u -> new CustomUser(u, Collections.emptyList()));
    }
}
