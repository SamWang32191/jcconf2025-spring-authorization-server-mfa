package tw.com.example.demo.authorizationserverdemo.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import tw.com.example.demo.authorizationserverdemo.security.MfaAuthentication;
import tw.com.example.demo.authorizationserverdemo.service.OtpService;

@Slf4j
@Controller
@RequiredArgsConstructor
public class OtpVerifyEntrypoint {

  private final OtpService otpService;

  @PostMapping("/mfa")
  public String verifyMFa(
      @RequestParam String otp,
      HttpSession session,
      HttpServletRequest request,
      HttpServletResponse response) {

    // 從session取出先前的MfaAuthentication
    MfaAuthentication mfaAuth = (MfaAuthentication) session.getAttribute("MFA_AUTH");
    if (mfaAuth == null) {
      return "redirect:/login?error";
    }

    UserDetails user = (UserDetails) mfaAuth.getPrincipal();
    // 驗證OTP
    if (!otpService.validateOtp(user.getUsername(), otp)) {
      // 驗證失敗
      return "redirect:/mfa?error";
    }
    // 驗證成功後，取出被我們放在MfaAuthentication中，原本的UsernamePasswordAuthenticationToken
    Authentication finalAuth = mfaAuth.getFirstFactorAuthentication();
    // 當前的SecurityContext裡的Authentication會是我們放的MfaAuthentication
    // 要把原本的UsernamePasswordAuthenticationToken放回去
    SecurityContextHolder.getContext().setAuthentication(finalAuth);
    SecurityContextRepository contextRepository = new HttpSessionSecurityContextRepository();
    contextRepository.saveContext(SecurityContextHolder.getContext(), request, response);

    // 從session 拿出original request url ，然後導過去
    String targetUrl = (String) session.getAttribute("MFA_ORIGINAL_REQUEST_URL");
    Optional.ofNullable(targetUrl)
        .ifPresentOrElse(
            url -> session.removeAttribute("MFA_ORIGINAL_REQUEST_URL"),
            () -> {
              throw new IllegalStateException("沒有找到Session中的原始請求URL");
            });
    session.removeAttribute("MFA_AUTH");
    log.info("MFA successfully verified. Redirecting to: {}", targetUrl);
    return "redirect:" + targetUrl;
  }
}
