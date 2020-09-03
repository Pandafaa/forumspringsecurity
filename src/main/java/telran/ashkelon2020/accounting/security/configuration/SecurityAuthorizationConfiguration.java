package telran.ashkelon2020.accounting.security.configuration;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityAuthorizationConfiguration extends WebSecurityConfigurerAdapter {
	
	@Override
	public void configure(WebSecurity web) {
		web.ignoring().antMatchers("/account/register");
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic();
		http.csrf().disable();
		http.authorizeRequests()
			.antMatchers(HttpMethod.GET).permitAll()
			.antMatchers(HttpMethod.POST, "/forum/posts/**").permitAll()
			.antMatchers("/account/user/{login}/role/{role}**").hasRole("ADMINISTRATOR")
			.antMatchers("/account/login**", "/forum/post/{id}/like**").hasAnyRole("ADMINISTRATOR", "MODERATOR", "USER")
			//.antMatchers(HttpMethod.DELETE, "/account/user/{login}**").
			.anyRequest().authenticated();
		
	}

}
