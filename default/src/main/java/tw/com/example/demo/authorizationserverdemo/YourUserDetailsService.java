package tw.com.example.demo.authorizationserverdemo;

import java.util.ArrayList;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class YourUserDetailsService implements UserDetailsService {

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    // implement your own logic to retrieve user details

    // for demo, we just return a hardcoded user
    return new User(username, "{noop}password", true, true, true, true, new ArrayList<>());
  }
}
