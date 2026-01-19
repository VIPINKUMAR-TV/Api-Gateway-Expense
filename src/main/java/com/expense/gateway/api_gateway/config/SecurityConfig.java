package com.expense.gateway.api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;


@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

	@Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            //.authorizeExchange(ex -> ex
            	   // .pathMatchers(
            	    	//	HttpMethod.OPTIONS, "/**",
            	       // "/actuator/health",
            	      //  "/auth/login",
            	      //  "/auth/register"
            	   // ).permitAll()
            	  //  .anyExchange().authenticated()
            	//)
            .authorizeExchange(ex -> ex.anyExchange().permitAll())
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
            .logout(ServerHttpSecurity.LogoutSpec::disable)
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .build();
    }
}