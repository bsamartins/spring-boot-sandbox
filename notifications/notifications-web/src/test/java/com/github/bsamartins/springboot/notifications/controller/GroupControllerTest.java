package com.github.bsamartins.springboot.notifications.controller;

import com.github.bsamartins.springboot.notifications.ApplicationIntegrationTest;
import com.github.bsamartins.springboot.notifications.domain.File;
import com.github.bsamartins.springboot.notifications.domain.GroupCreate;
import com.github.bsamartins.springboot.notifications.domain.persistence.Group;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.mongodb.core.ReactiveMongoTemplate;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.web.reactive.function.BodyInserters.fromObject;

public class GroupControllerTest extends ApplicationIntegrationTest {

    @Autowired
    private WebTestClient webClient;

    @Autowired
    private ReactiveMongoTemplate reactiveMongoTemplate;

    @BeforeEach
    public void setup() {
    }

    @Test
    public void create() {
        File file = new File();
        file.setContent("Hello World".getBytes());
        file.setName("image.txt");
        file.setMediaType(MediaType.valueOf("plain/text"));

        GroupCreate groupCreate = new GroupCreate();
        groupCreate.setName("test group");
        groupCreate.setPicture(file);

        Group result = webClient.post().uri("/api/groups")
                .body(fromObject(groupCreate))
                .headers(headers -> {
                    headers.setContentType(MediaType.APPLICATION_JSON);
                })
                .headers(withUser())
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isOk()
                .expectBody(Group.class)
                .returnResult()
                .getResponseBody();
        assertNotNull(result);
    }

    @AfterEach
    public void tearDown() {
        Mono.from(this.reactiveMongoTemplate.getMongoDatabase().drop())
                .subscribe();
    }
}
