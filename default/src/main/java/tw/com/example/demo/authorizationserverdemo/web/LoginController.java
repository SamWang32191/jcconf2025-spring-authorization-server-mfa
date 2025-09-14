package tw.com.example.demo.authorizationserverdemo.web;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Slf4j
@Controller
@RequiredArgsConstructor
public class LoginController {

  @GetMapping("/login")
  public String login() {
    return "login";
  }
}
