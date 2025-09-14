package tw.com.example.demo.authorizationserverdemo.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

/**
 * 此類別負責處理用戶成功登入後的行為，並實作 {@link AuthenticationSuccessHandler} 介面。 當用戶成功登入後，會將原始請求 URL 暫存至 Session
 * 中，然後將用戶導向 MFA（Multi-Factor Authentication，多因素驗證）頁面。
 */
@Slf4j
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {

  private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  /**
   * 在用戶成功進行身份驗證後執行的處理邏輯。 將原始請求 URL 暫存於 Session 中，並將用戶重導至 MFA 驗證頁面。
   *
   * @param request HTTP 請求物件，包含當前請求的相關訊息。
   * @param response HTTP 回應物件，用於發送重導指令。
   * @param authentication 用戶的認證訊息，包含的細節如用戶名及授權資訊。
   * @throws IOException 當重導過程中發生 I/O 錯誤時拋出。
   */
  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException {

    // 使用 HttpSessionRequestCache 來存取/取得先前因未授權而被保存於 Session 的原始請求資訊（例如登入前想前往的 URL）
    RequestCache requestCache = new HttpSessionRequestCache();
    // 從快取中取回前次被攔截並保存的請求物件，用於後續決定成功登入後要重導至哪裡
    SavedRequest savedRequest = requestCache.getRequest(request, response);
    // 自 SavedRequest 取得原始欲重導的目標 URL
    String originalRequestUrl = savedRequest.getRedirectUrl();
    // 先暫存此 URL 以便 Mfa 完成後再導回
    request.getSession().setAttribute("MFA_AUTH", authentication);
    request.getSession().setAttribute("MFA_ORIGINAL_REQUEST_URL", originalRequestUrl);
    redirectStrategy.sendRedirect(request, response, "/mfa");
  }
}
