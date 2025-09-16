package tw.com.example.demo.authorizationserverdemo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

  /**
   * 配置預設的 {@link SecurityFilterChain} 安全篩選器鏈。 此方法設定應用程式的安全配置，包括授權請求的規則和登入頁面的配置。
   *
   * @param http 用於配置 HTTP 安全性的 {@link HttpSecurity} 實例。
   * @return 已配置完成的 {@link SecurityFilterChain} 實例。
   * @throws Exception 當執行配置過程中發生異常時拋出。
   */
  @Bean
  public SecurityFilterChain defaultSecurityFilterChain(
      HttpSecurity http, CustomAuthenticationProvider authenticationProvider) throws Exception {

    http.authorizeHttpRequests(
            authorize ->
                authorize
                    .requestMatchers("/assets/**", "/login", "/mfa")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .authenticationProvider(authenticationProvider) // <--- 在這裡註冊我們的 Provider
        .formLogin(
            formLogin ->
                formLogin
                    .loginPage("/login")
                    .successHandler(new CustomLoginSuccessHandler())  // <--- 在這裡註冊我們的 Handler
        );

    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    // just for demo, don't use this in production
    return NoOpPasswordEncoder.getInstance();
  }

  @Bean
  public SessionRegistry sessionRegistry() {
    return new SessionRegistryImpl();
  }

  @Bean
  public HttpSessionEventPublisher httpSessionEventPublisher() {
    return new HttpSessionEventPublisher();
  }
}
