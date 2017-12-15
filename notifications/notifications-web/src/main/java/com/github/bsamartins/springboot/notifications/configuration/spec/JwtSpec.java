package com.github.bsamartins.springboot.notifications.configuration.spec;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.ServerHttpBasicAuthenticationConverter;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.HttpBasicServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;

import java.util.Collections;

public class JwtSpec {
//		private ReactiveAuthenticationManager authenticationManager;
//
//		private ServerSecurityContextRepository securityContextRepository = NoOpServerSecurityContextRepository.getInstance();
//
//		private ServerAuthenticationEntryPoint entryPoint = new HttpBasicServerAuthenticationEntryPoint();
//
//		public JwtSpec authenticationManager(ReactiveAuthenticationManager authenticationManager) {
//			this.authenticationManager = authenticationManager;
//			return this;
//		}
//
//		public JwtSpec securityContextRepository(ServerSecurityContextRepository securityContextRepository) {
//			this.securityContextRepository = securityContextRepository;
//			return this;
//		}
//
//		public ServerHttpSecurity and() {
//			return ServerHttpSecurity.this;
//		}
//
//		public ServerHttpSecurity disable() {
//			ServerHttpSecurity.this.httpBasic = null;
//			return ServerHttpSecurity.this;
//		}
//
//		protected void configure(ServerHttpSecurity http) {
//			MediaTypeServerWebExchangeMatcher restMatcher = new MediaTypeServerWebExchangeMatcher(
//				MediaType.APPLICATION_ATOM_XML,
//				MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON,
//				MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_XML,
//				MediaType.MULTIPART_FORM_DATA, MediaType.TEXT_XML);
//			restMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
//			ServerHttpSecurity.this.defaultEntryPoints.add(new DelegatingServerAuthenticationEntryPoint.DelegateEntry(restMatcher, this.entryPoint));
//			AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(
//				this.authenticationManager);
//			authenticationFilter.setAuthenticationFailureHandler(new ServerAuthenticationEntryPointFailureHandler(this.entryPoint));
//			authenticationFilter.setAuthenticationConverter(new ServerHttpBasicAuthenticationConverter());
//			if(this.securityContextRepository != null) {
//				authenticationFilter.setSecurityContextRepository(this.securityContextRepository);
//			}
//			http.addFilterAt(authenticationFilter, SecurityWebFiltersOrder.HTTP_BASIC);
//		}
//
//		private JwtSpec() {}
	}