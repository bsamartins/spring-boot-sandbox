package com.github.bsamartins.springboot.notifications.configuration;

import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.bsamartins.springboot.notifications.controller.handler.FileHandler;
import com.github.bsamartins.springboot.notifications.jackson.deserializer.MediaTypeDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.config.ResourceHandlerRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;

import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RequestPredicates.accept;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

@Configuration
@EnableWebFlux
public class WebConfig implements WebFluxConfigurer {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebFluxConfigurer.class);

    @Value("${app.ui.resources-location:classpath:/notifications-ui/}")
    private String resourcesLocation;

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        LOGGER.debug("Mapping resources from {}", resourcesLocation);
        registry.addResourceHandler("/**")
                .addResourceLocations(resourcesLocation);
    }

    @Bean
    public com.fasterxml.jackson.databind.Module jacksonJavaTimeModule() {
        return new JavaTimeModule();
    }

    @Bean
    public SimpleModule jacksonCustomModule() {
        SimpleModule module = new SimpleModule();
        module.addDeserializer(MediaType.class, new MediaTypeDeserializer());
        return module;
    }

    @Bean
    public RouterFunction<ServerResponse> files(FileHandler fileHandler) {
        return route(GET("/api/files/{id}").and(accept(MediaType.APPLICATION_JSON)), fileHandler::findById);
    }
}