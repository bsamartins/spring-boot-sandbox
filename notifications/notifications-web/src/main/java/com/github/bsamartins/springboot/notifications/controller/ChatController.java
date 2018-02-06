package com.github.bsamartins.springboot.notifications.controller;

import com.github.bsamartins.springboot.notifications.domain.ChatCreate;
import com.github.bsamartins.springboot.notifications.domain.persistence.Chat;
import com.github.bsamartins.springboot.notifications.service.ChatService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;

@RestController
@RequestMapping("/api/chats")
public class ChatController {

    @Autowired
    private ChatService chatService;

    @GetMapping(value = "/{id}")
    public Mono<ResponseEntity<Chat>> findById(@PathVariable("id") String id) {
        return chatService.findById(id)
                .map(ResponseEntity::ok)
                .switchIfEmpty(Mono.just(ResponseEntity.notFound().build()));
    }

    @GetMapping
    public Mono<List<Chat>> findAll() {
        return chatService.findAll().collectList();
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public Mono<Chat> create(@RequestBody ChatCreate chat) {
        return chatService.create(new Chat(chat), chat.getPicture())
                .cast(Chat.class)
                .switchIfEmpty(Mono.error(new Exception("what?")))
                .log();
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public Mono<Chat> postMembership(@RequestBody ChatCreate chat) {
        return chatService.create(new Chat(chat), chat.getPicture())
                .cast(Chat.class)
                .switchIfEmpty(Mono.error(new Exception("what?")))
                .log();
    }

}