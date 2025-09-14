package tw.com.example.demo.authorizationserverdemo.security;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * 設置授權伺服器的配置類別，此類別定義了授權伺服器的多個核心設置與功能，包括安全性篩選器鏈的配置、OAuth 客戶端註冊儲存庫、JWKSource、 JWT
 * 解碼器等。該類別主要用於建立與配置授權伺服器所需的各種元件，以實現 OAuth2 與 OpenID Connect 協議所需的功能。
 *
 * <p>主要功能包括：
 *
 * <ul>
 *   <li>配置授權伺服器的安全性篩選器鏈，支援 OpenID Connect 1.0（OIDC）及錯誤處理行為。
 *   <li>管理 OAuth2 客戶端的註冊與設定，包括令牌壽命與客戶端設定。
 *   <li>創建 JSON Web Key (JWK) 的公私鑰對，以支援 JWK 操作及安全性功能。
 *   <li>在授權伺服器中啟用 JWT 解碼器，支援 OpenID Connect 的使用者資訊端點及客戶端註冊。
 * </ul>
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

  /**
   * 提供一個配置授權伺服器的 {@link SecurityFilterChain} 以管理安全性篩選器鏈。 此方法設置授權伺服器的安全性需求，如 OpenID Connect (OIDC)
   * 支援、 用戶資訊端點 (UserInfo Endpoint) 的映射配置、以及 HTTP 請求驗證與例外處理等。
   *
   * @param http 用於配置 HTTP 安全性的 {@link HttpSecurity} 實例。
   * @return 回傳已配置完成的 {@link SecurityFilterChain} 實例。
   * @throws Exception 當配置過程中發生異常時拋出。
   */
  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
      throws Exception {
    final OAuth2AuthorizationServerConfigurer configurer =
        OAuth2AuthorizationServerConfigurer.authorizationServer();
    http.securityMatcher(configurer.getEndpointsMatcher())
        .with(
            configurer,
            serverConfigurer ->
                serverConfigurer.oidc(Customizer.withDefaults())) // Enable OpenID Connect 1.0
        .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
        .exceptionHandling(
            (exceptions) ->
                exceptions.defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
    return http.build();
  }

  /**
   * oauth client registered repository
   *
   * <p>demo用才hardcode，應透過環境變數等外部注入
   */
  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    // token expire time setting
    final TokenSettings tokenSettings =
        TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofMinutes(5))
            .refreshTokenTimeToLive(Duration.ofMinutes(30))
            .build();
    // client setting enable PKCE and disable consent
    final ClientSettings clientSettings =
        ClientSettings.builder()
            .requireProofKey(true) // PKCE
            .requireAuthorizationConsent(false) // consent
            .build();
    // client registration
    final RegisteredClient oidcClient =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("client-id")
            .clientSecret("123456")
            .redirectUri("https://oauth.pstmn.io/v1/callback")
            .scope("openid")
            .scope("profile")
            .scope("email")
            .scope("groups")
            .authorizationGrantType(AUTHORIZATION_CODE)
            .authorizationGrantType(REFRESH_TOKEN)
            .clientAuthenticationMethod(CLIENT_SECRET_BASIC)
            .clientSettings(clientSettings)
            .tokenSettings(tokenSettings)
            .build();
    return new InMemoryRegisteredClientRepository(oidcClient);
  }

  /**
   * 構建並提供一個 {@link JWKSource} 實例，該實例包含 RSA 公私鑰對作為 JSON Web Key (JWK) 集合的一部分。 此方法使用動態生成的 RSA 金鑰對來創建
   * JWK 集合，並將其包裝為一個不可變的 JWKSource 物件。
   *
   * @return 一個用於處理安全性的 {@link JWKSource} 實例，包含了動態生成的 RSA 公私鑰對 JWK 集合。
   */
  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    final KeyPair keyPair = generateRsaKey();
    final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    final RSAKey rsaKey =
        new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
    final JWKSet jwkSet = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(jwkSet);
  }

  /**
   * 生成一個新的 RSA 公私鑰對。
   *
   * @return 回傳包含動態生成的 RSA 公鑰與私鑰的 {@link KeyPair} 物件。
   * @throws IllegalStateException 當生成過程中發生錯誤時拋出。
   */
  private static KeyPair generateRsaKey() {
    try {
      final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      return keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
  }

  /**
   * JWTDecoder is REQUIRED for the OpenID Connect 1.0 UserInfo endpoint and the OpenID Connect 1.0
   * Client Registration
   */
  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  /**
   * 提供一個配置授權伺服器設定的 {@link AuthorizationServerSettings} 實例。 該方法透過建造者模式生成並返回一個預設設置的授權伺服器設定物件。
   *
   * @return 返回一個 {@link AuthorizationServerSettings} 實例，用於配置授權伺服器的相關設定。
   */
  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }
}
