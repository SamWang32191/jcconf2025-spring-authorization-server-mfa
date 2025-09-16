package tw.com.example.demo.authorizationserverdemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
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

}
