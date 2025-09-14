package tw.com.example.demo.authorizationserverdemo.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class OtpService {

  public void generateAndSendOtp(String username) {

    // generate OTP , send to user and save the OTP for verify

  }

  public boolean validateOtp(String username, String otp) {
    // validate OTP
    return true;
  }
}
