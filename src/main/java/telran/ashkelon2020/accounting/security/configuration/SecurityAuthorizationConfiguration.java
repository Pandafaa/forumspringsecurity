package telran.ashkelon2020.accounting.security.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

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

		http.csrf().disable();  // cross site request forgery (межсайтовая подделка запроса.
//		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//		String currentPrincipalName = authentication.getName();
//	System.out.println("auhtenticatin"+ authentication);
//	System.out.println("name"+currentPrincipalName);
		// http.authorizeRequests().anyRequest().permitAll(); //permits to anyOne to make any request
		// http.authorizeRequests().anyRequest().authenticated(); //permits to autenticate users and wtih NO auth

		
		http.authorizeRequests()
			.antMatchers(HttpMethod.GET).permitAll()    // all Get requests permitted
			.antMatchers(HttpMethod.POST, "/forum/posts/**").permitAll()  // only matching endpoimts and Methods permited   
			.antMatchers("/account/user/{login}/role/{role}**")
				.hasRole("ADMINISTRATOR")                                     // endpoint and user  HasRole  ( validate Administrator)
	 
			.antMatchers(HttpMethod.DELETE,"/account/user/{login}**")   //delete account
				.access("#login==authentication.name")                                    // pathvariable  login must satisfy access condition(validate user)
			.antMatchers(HttpMethod.PUT,"/forum/post/{id}")  //update post
				.access("@customSecurity.checkExpDate(authentication.name) and @customSecurity.checkHasRoles(authentication.name)"
						+ "and @customSecurity.checkPostAuthority(#id, authentication.name) or hasRole('MODERATOR')")
				.antMatchers(HttpMethod.DELETE,"/forum/post/{id}**")           //delete post
				.access("@customSecurity.checkExpDate(authentication.name) and @customSecurity.checkHasRoles(authentication.name)"
						+ "and @customSecurity.checkPostAuthority(#id, authentication.name) or hasRole('MODERATOR')")
	
			.antMatchers("/account/password**")  //change password
					.authenticated()
					.antMatchers(HttpMethod.PUT,"/account/user/{login}**")           //update account
					.access("#login==authentication.name and @customSecurity.checkExpDate(authentication.name) "
							+ "and @customSecurity.checkHasRoles(authentication.name)")    
	.antMatchers("/account/login**", "/forum/post/{id}/like**")         //login or add like
	.access("@customSecurity.checkExpDate(authentication.name) and @customSecurity.checkHasRoles(authentication.name)")  //checks for toles and expDate
	.antMatchers(HttpMethod.PUT, "/forum/post/{id}/comment/{author}")
	.access("#author == authentication.name and @customSecurity.checkExpDate(authentication.name) "
			+ "and @customSecurity.checkHasRoles(authentication.name)")
	.antMatchers(HttpMethod.POST, "/forum/post/{author}**")
	.access("#author ==authentication.name and @customSecurity.checkExpDate(authentication.name)"
			+ " and hasAnyRole('ADMINISTRATOR', 'MODERATOR', 'USER')")   // can use this for specific role or checkorole method for any role
			
	.anyRequest()
					.authenticated();
			

		
	}

}
