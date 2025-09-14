package tw.com.example.demo.authorizationserverdemo.web;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * LoginController 提供處理用戶登入及雙因素驗證頁面導向的功能。
 * 該控制器負責處理與登入相關的請求，並提供相應的視圖。
 *
 * <p>功能摘要：
 * <ul>
 *   <li>提供用戶登入頁面：映射至 "/login" 的 GET 請求，返回登入頁面視圖。</li>
 *   <li>提供雙因素驗證頁面：映射至 "/mfa" 的 GET 請求，返回雙因素驗證頁面視圖。</li>
 * </ul>
 */
@Slf4j
@Controller
@RequiredArgsConstructor
public class LoginController {

  @GetMapping("/login")
  public String login() {
    return "login";
  }

  @GetMapping("/mfa")
  public String mfaPage() {
    return "mfa";
  }
}
