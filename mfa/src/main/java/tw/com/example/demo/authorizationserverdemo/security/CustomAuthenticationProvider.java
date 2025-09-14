package tw.com.example.demo.authorizationserverdemo.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import tw.com.example.demo.authorizationserverdemo.service.OtpService;

@Service
public class CustomAuthenticationProvider extends DaoAuthenticationProvider {

  private final OtpService otpService;

  public CustomAuthenticationProvider(
      UserDetailsService userDetailsService, OtpService otpService) {
    super(userDetailsService);
    this.otpService = otpService;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    // 首先，使用父類別的邏輯驗證使用者名稱和密碼
    Authentication firstFactorAuthentication = super.authenticate(authentication);

    // 如果使用者名稱和密碼驗證成功
    UserDetails user = (UserDetails) firstFactorAuthentication.getPrincipal();

    // 產生並發送 OTP
    otpService.generateAndSendOtp(user.getUsername());

    // 返回一個代表「需要 MFA」的中間狀態
    return new MfaAuthentication(firstFactorAuthentication);
  }

  @Override
  public boolean supports(Class<?> authentication) {
    // 這個 Provider 只支援 UsernamePasswordAuthenticationToken
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
