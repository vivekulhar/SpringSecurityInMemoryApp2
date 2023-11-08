package dev.vivek.springsecurityinmemoryapp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.ldap.EmbeddedLdapServerContextSourceFactoryBean;
import org.springframework.security.config.ldap.LdapBindAuthenticationManagerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.PersonContextMapper;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import static org.springframework.security.config.Customizer.withDefaults;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
    /*
    * This is required to enable the authentication manager bean
    * */
    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user1 = User.withDefaultPasswordEncoder()
                .username("devs")
                .password("devs")
                .roles("ADMIN")
                .build();
        UserDetails user2 = User.withDefaultPasswordEncoder()
                .username("es")
                .password("devs")
                .roles("EMPLOYEE")
                .build();
        UserDetails user3 = User.withDefaultPasswordEncoder()
                .username("ms")
                .password("devs")
                .roles("MANAGER")
                .build();
        return new InMemoryUserDetailsManager(user1, user2, user3);
    }

    /*
    * This is required to enable the authorization manager bean
    * */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authz) -> authz
                        .requestMatchers("/home").permitAll()
                        .requestMatchers("/welcome").authenticated()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/emp").hasRole("EMPLOYEE")
                        .requestMatchers("/mgr").hasRole("MANAGER")
                        .requestMatchers("/common").hasAnyRole("ADMIN", "EMPLOYEE", "MANAGER")
                        .anyRequest().authenticated())
                .formLogin(formLogin->formLogin.defaultSuccessUrl("/welcome", true))
                .logout(logout->logout.logoutSuccessUrl("/logout"))
                .exceptionHandling(exceptionHandling->exceptionHandling.accessDeniedPage("/accessDenied"));


        return http.build();
    }
}
