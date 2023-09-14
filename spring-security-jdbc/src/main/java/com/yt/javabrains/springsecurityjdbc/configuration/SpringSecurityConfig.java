package com.yt.javabrains.springsecurityjdbc.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;
import java.util.function.Function;

@EnableWebSecurity
@Configuration
public class SpringSecurityConfig {


    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    @Bean
    public UserDetailsManager users(DataSource dataSource) {
        UserDetails user1 = createNewUser("user1","pass","USER");
        UserDetails admin1 = createNewUser("admin1","pass","ADMIN");
        UserDetails user2 = createNewUser("user2","pass","USER");

        JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
        users.createUser(user1);
        users.createUser(admin1);
        users.createUser(user2);
        return users;
    }

    private static UserDetails createNewUser(String userName,String password,String role) {
        Function<String, String> passwordEncoder = input -> passwordEncoder().encode(input);
        UserDetails user = User.builder()
                .passwordEncoder(passwordEncoder)
                .username(userName)
                .password(password)
                .roles(role)
                .build();
        return user;
    }

    @Bean
    public static BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.authorizeHttpRequests()
                .requestMatchers(new AntPathRequestMatcher("/admin")).hasRole("ADMIN")
                .requestMatchers(new AntPathRequestMatcher("/user")).hasAnyRole("USER","ADMIN")
                .requestMatchers(new AntPathRequestMatcher("/")).permitAll();
//                .requestMatchers(new AntPathRequestMatcher("/h2-console")).permitAll();

        httpSecurity.formLogin(Customizer.withDefaults());

        return httpSecurity.build();
    }
}
