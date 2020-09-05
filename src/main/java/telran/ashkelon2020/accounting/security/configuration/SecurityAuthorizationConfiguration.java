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
		http.csrf().disable();// cross site request forgery (межсайтовая подделка запроса.
		// http.authorizeRequests().anyRequest().permitAll(); //permits to anyOne to
		// makr any request
		// http.authorizeRequests().anyRequest().authenticated(); //permits to
		// autenticated users and wtih NO auth
		http.authorizeRequests().antMatchers(HttpMethod.GET).permitAll() // all Get requests permitted
				.antMatchers(HttpMethod.POST, "/forum/posts/**").permitAll() // only matching endpoimts and Methods permited
																				
				.antMatchers("/account/user/{login}/role/{role}**").hasRole("ADMINISTRATOR") // endpoint and user  HasRole
																								
				.antMatchers("/account/login**", "/forum/post/{id}/like**")
				.hasAnyRole("ADMINISTRATOR", "MODERATOR", "USER") // endpoint and role from a list
				.antMatchers("/account/user/{login}**").access("#login==authentication.name") // var ligin must satisfy
																								// access condition
				.antMatchers(HttpMethod.PUT, "forum/post/{id}**").access("@customSecurity.checkPosAuthority(#id,authentication.name) or"
						+ "hasRole(*"MODERATOR"*)")
				// .antMatchers(HttpMethod.DELETE, "/account/user/{login}**").
				.anyRequest().authenticated();

		http.csrf().disable();
		http.authorizeRequests()
			.antMatchers(HttpMethod.GET).permitAll()
			.antMatchers(HttpMethod.POST, "/forum/posts/**").permitAll()
			.antMatchers("/account/user/{login}/role/{role}**")
				.hasRole("ADMINISTRATOR")
			.antMatchers("/account/login**", "/forum/post/{id}/like**")
				.hasAnyRole("ADMINISTRATOR", "MODERATOR", "USER")
			.antMatchers("/account/user/{login}**")
				.access("#login==authentication.name")
			.antMatchers(HttpMethod.PUT,"/forum/post/{id}**")
				.access("@customSecurity.checkPostAuthority(#id, authentication.name) or hasRole('MODERATOR')")
			.antMatchers("/account/password**")
				.authenticated()
			.anyRequest()
				.authenticated();
		
		http.csrf().disable();
		http.authorizeRequests()
			.antMatchers(HttpMethod.GET).permitAll()
			.antMatchers(HttpMethod.POST, "/forum/posts/**").permitAll()
			.antMatchers("/account/user/{login}/role/{role}**")
				.hasRole("ADMINISTRATOR")
			.antMatchers("/account/login**", "/forum/post/{id}/like**")
				.hasAnyRole("ADMINISTRATOR", "MODERATOR", "USER")
			.antMatchers("/account/user/{login}**")
				.access("#login==authentication.name")
			.antMatchers(HttpMethod.PUT,"/forum/post/{id}**")
				.access("@customSecurity.checkPostAuthority(#id, authentication.name) or hasRole('MODERATOR')")
			.antMatchers("/account/password**")
				.authenticated()
			.anyRequest()
				.authenticated();
		
		http.csrf().disable();
		http.authorizeRequests()
			.antMatchers(HttpMethod.GET).permitAll()
			.antMatchers(HttpMethod.POST, "/forum/posts/**").permitAll()
			.antMatchers("/account/user/{login}/role/{role}**")
				.hasRole("ADMINISTRATOR")
			.antMatchers("/account/login**", "/forum/post/{id}/like**")
				.hasAnyRole("ADMINISTRATOR", "MODERATOR", "USER")
			.antMatchers("/account/user/{login}**")
				.access("#login==authentication.name")
			.antMatchers(HttpMethod.PUT,"/forum/post/{id}**")
				.access("@customSecurity.checkPostAuthority(#id, authentication.name) or hasRole('MODERATOR')")
			.antMatchers("/account/password**")
				.authenticated()
			.anyRequest()
				.authenticated();
		
		http.csrf().disable();
		http.authorizeRequests()
			.antMatchers(HttpMethod.GET).permitAll()
			.antMatchers(HttpMethod.POST, "/forum/posts/**").permitAll()
			.antMatchers("/account/user/{login}/role/{role}**")
				.hasRole("ADMINISTRATOR")
			.antMatchers("/account/login**", "/forum/post/{id}/like**")
				.hasAnyRole("ADMINISTRATOR", "MODERATOR", "USER")
			.antMatchers("/account/user/{login}**")
				.access("#login==authentication.name")
			.antMatchers(HttpMethod.PUT,"/forum/post/{id}**")
				.access("@customSecurity.checkPostAuthority(#id, authentication.name) or hasRole('MODERATOR')")
			.antMatchers("/account/password**")
				.authenticated()
			.anyRequest()
				.authenticated();
		
		http.csrf().disable();
		http.authorizeRequests()
			.antMatchers(HttpMethod.GET).permitAll()
			.antMatchers(HttpMethod.POST, "/forum/posts/**").permitAll()
			.antMatchers("/account/user/{login}/role/{role}**")
				.hasRole("ADMINISTRATOR")
			.antMatchers("/account/login**", "/forum/post/{id}/like**")
				.hasAnyRole("ADMINISTRATOR", "MODERATOR", "USER")
			.antMatchers("/account/user/{login}**")
				.access("#login==authentication.name")
			.antMatchers(HttpMethod.PUT,"/forum/post/{id}**")
				.access("@customSecurity.checkPostAuthority(#id, authentication.name) or hasRole('MODERATOR')")
			.antMatchers("/account/password**")
				.authenticated()
			.anyRequest()
				.authenticated();
		
	}

}
