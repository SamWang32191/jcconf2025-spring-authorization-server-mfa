package tw.com.example.demo.authorizationserverdemo.security;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

/** 代表一個需要進行 MFA 驗證的中間狀態。 這個物件本身是「未驗證」的 (isAuthenticated() = false)。 */
@Getter
public class MfaAuthentication extends AbstractAuthenticationToken {

  private final Authentication firstFactorAuthentication;

  public MfaAuthentication(Authentication firstFactorAuthentication) {
    super(null); // 沒有 authorities
    this.firstFactorAuthentication = firstFactorAuthentication;
    setAuthenticated(false); // 明確設定為未驗證
  }

  @Override
  public Object getCredentials() {
    return firstFactorAuthentication.getCredentials();
  }

  @Override
  public Object getPrincipal() {
    return firstFactorAuthentication.getPrincipal();
  }
}
