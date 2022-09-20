package com.anodiam.gateway.config;

import com.anodiam.gateway.data.model.AnodiamUser;
import com.anodiam.gateway.data.service.AnodiamUserService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.SneakyThrows;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class SocialTokenRelayGatewayFilterFactory extends AbstractGatewayFilterFactory<Object> {

    @Value("${spring.security.anodiam.jwt.secret}")
    private String jwtSectet;

    private final ObjectProvider<ReactiveOAuth2AuthorizedClientManager> clientManagerProvider;
    private final AnodiamUserService anodiamUserService;

    public SocialTokenRelayGatewayFilterFactory(ObjectProvider<ReactiveOAuth2AuthorizedClientManager> clientManagerProvider, AnodiamUserService anodiamUserService) {
        super(Object.class);
        this.clientManagerProvider = clientManagerProvider;
        this.anodiamUserService = anodiamUserService;
    }

    @Override
    public String name() {
        return "SocialTokenRelay";
    }

    public GatewayFilter apply() {
        return apply((Object) null);
    }

    @Override
    public GatewayFilter apply(Object config) {
        return (exchange, chain) -> exchange.getPrincipal()
                .filter(principal -> principal instanceof OAuth2AuthenticationToken)
                .cast(OAuth2AuthenticationToken.class)
                .flatMap(authentication -> authorizedClient(exchange, authentication))
                .map(principal -> withBearerToken(exchange, principal))
                .defaultIfEmpty(exchange).flatMap(chain::filter);
    }

    private Mono<OAuth2User> authorizedClient(ServerWebExchange exchange,
                                              OAuth2AuthenticationToken oauth2Authentication) {
        final String clientRegistrationId = oauth2Authentication.getAuthorizedClientRegistrationId();
        OAuth2AuthorizeRequest request = OAuth2AuthorizeRequest.withClientRegistrationId(clientRegistrationId)
                .principal(oauth2Authentication).build();
        ReactiveOAuth2AuthorizedClientManager clientManager = clientManagerProvider.getIfAvailable();
        if (clientManager == null) {
            return Mono.error(new IllegalStateException(
                    "No ReactiveOAuth2AuthorizedClientManager bean was found. Did you include the "
                            + "org.springframework.boot:spring-boot-starter-oauth2-client dependency?"));
        }
        Collection<? extends GrantedAuthority> authorities = oauth2Authentication.getPrincipal().getAuthorities();
        Map<String, Object> attributes = oauth2Authentication.getPrincipal().getAttributes();
        return clientManager
                .authorize(request)
                .map(OAuth2AuthorizedClient::getAccessToken)
                .map(accessToken -> mutateUser(accessToken, authorities, attributes, clientRegistrationId));
    }

    private OAuth2User mutateUser(OAuth2AccessToken accessToken, Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes, final String provider) {
        Map<String, Object> mutableAttributes = new LinkedHashMap<>(attributes);
        mutableAttributes.put("iat", accessToken.getIssuedAt());
        mutableAttributes.put("exp", accessToken.getExpiresAt());
        mutableAttributes.put("provider", provider);
        return new DefaultOAuth2User(authorities, mutableAttributes, "name");
    }

    private ServerWebExchange withBearerToken(ServerWebExchange exchange, OAuth2User principal) {
        AnodiamUser anodiamUser = anodiamUserService.saveOrGet(buildUserDetails(principal));
        Map<String, Object> mutableAttributes = new LinkedHashMap<>(principal.getAttributes());
        Collection<? extends GrantedAuthority> authorities = anodiamUser.getRoles().stream().map(role -> new SimpleGrantedAuthority(role.getName())).collect(Collectors.toUnmodifiableSet());
        OAuth2User anodiamPrincipal = new DefaultOAuth2User(authorities, mutableAttributes, "name");
        return exchange.mutate().request(r -> r.headers(headers -> headers.setBearerAuth(getJwt(anodiamPrincipal)))).build();
    }

    private AnodiamUser buildUserDetails(OAuth2User principal) {
        AnodiamUser anodiamUser = new AnodiamUser();
        anodiamUser.setEmail(principal.getAttribute("email"));
        anodiamUser.setProvider(principal.getAttribute("provider"));
        return anodiamUser;
    }

    @SneakyThrows
    private String getJwt(OAuth2User principal) {
        Key hmacKey = new SecretKeySpec(Base64.getDecoder().decode(jwtSectet),
                SignatureAlgorithm.HS256.getJcaName());
        Map<String, Object> principalAttributes =
                principal.getAttributes()
                .entrySet().stream()
                        .filter(entry -> !Objects.equals(entry.getKey(), "iat") && !Objects.equals(entry.getKey(), "exp"))
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        return Jwts.builder()
                .claim("attributes", principalAttributes)
                .claim("authorities", principal.getAuthorities())
                .setSubject(principal.getAttribute("name"))
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(Date.from(((Instant) principal.getAttributes().get("iat"))))
                .setExpiration(Date.from(((Instant) principal.getAttributes().get("exp"))))
                .signWith(hmacKey, SignatureAlgorithm.HS256)
                .compact();
    }

}