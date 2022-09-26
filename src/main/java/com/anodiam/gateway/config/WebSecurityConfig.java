package com.anodiam.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebFluxSecurity
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true)
public class WebSecurityConfig {

    @Bean
    public SecurityWebFilterChain configure(ServerHttpSecurity http, ReactiveClientRegistrationRepository clientRegistrationRepository) {
        http.logout().disable();
        http.csrf().disable()
                .authorizeExchange()
                .pathMatchers("/login", "/login/oauth2", "/oauth2", "/auth/**", "/oauth2/**").permitAll()
                .anyExchange()
                .authenticated()
                .and()
                .oauth2Login(withDefaults())
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(new RedirectServerAuthenticationEntryPoint("/login/oauth2"))
                )
                .oauth2Login(oauth2 -> oauth2
                        .authorizationRequestResolver(this.authorizationRequestResolver(clientRegistrationRepository))
                );
        http.addFilterBefore(new AnodiamAuthenticationFilter(), SecurityWebFiltersOrder.AUTHENTICATION);
        return http.build();
    }

    private ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver(ReactiveClientRegistrationRepository clientRegistrationRepository) {
        ServerWebExchangeMatcher authorizationRequestMatcher =
                new PathPatternParserServerWebExchangeMatcher(
                        "/login/oauth2/authorization/{registrationId}");

        return new DefaultServerOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository, authorizationRequestMatcher);
    }
}
