package com.github.bsamartins.springboot.notifications.configuration;

import org.springframework.context.annotation.Configuration;

@Configuration
//@EnableAuthorizationServer
public class AuthorizationServerConfig //extends AuthorizationServerConfigurerAdapter
{

//	@Value("${security.jwt.client-id}")
//	private String clientId;
//
//	@Value("${security.jwt.client-secret}")
//	private String clientSecret;

//	@Value("${security.jwt.grant-type}")
//	private String grantType;
//
//	@Value("${security.jwt.scope-read}")
//	private String scopeRead;
//
//	@Value("${security.jwt.scope-write}")
//	private String scopeWrite = "write";
//
//	@Value("${security.jwt.resource-ids}")
//	private String resourceIds;

//	@Autowired
//	private TokenStore tokenStore;
//
//	@Autowired
//	private JwtAccessTokenConverter accessTokenConverter;
//
//	@Autowired
//	private AuthenticationManager authenticationManager;
//
//
//
//	@Override
//	public void configure(ClientDetailsServiceConfigurer configurer) throws Exception {
//		configurer
//		        .inMemory()
//		        .withClient(clientId)
//		        .secret(clientSecret)
////		        .authorizedGrantTypes(grantType)
////		        .scopes(scopeRead, scopeWrite)
////		        .resourceIds(resourceIds)
//		;
//	}
//
//	@Override
//	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//		TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
//		enhancerChain.setTokenEnhancers(Arrays.asList(accessTokenConverter));
//		endpoints.tokenStore(tokenStore)
//		        .accessTokenConverter(accessTokenConverter)
//		        .tokenEnhancer(enhancerChain)
//		        .authenticationManager(authenticationManager);
//	}
//
}
