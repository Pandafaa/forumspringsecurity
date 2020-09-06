package telran.ashkelon2020.accounting.security.service;

import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import telran.ashkelon2020.accounting.dao.UserAccountRepository;
import telran.ashkelon2020.accounting.model.UserAccount;

@Service
public class UserDetailsSetviceImpl implements UserDetailsService {  //* Core interface which loads user-specific data. by method loadUserByUsername
	
	@Autowired
	UserAccountRepository accountRepository;


	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {  // * Provides core user information.
		UserAccount userAccount = accountRepository.findById(username)
				.orElseThrow(() -> new UsernameNotFoundException(username));
	boolean credentialsNonExpired =	userAccount.getExpDate().isAfter(LocalDateTime.now());
//	System.out.println("credentialsNonExpired "+credentialsNonExpired);
	
		String[] roles = userAccount.getRoles()
				.stream()
				.map(r -> "ROLE_" + r.toUpperCase())     //syntax for storing role in AuthorityList
				.toArray(String[]::new);
		User user =	new User(username, userAccount.getPassword(),    //  create User with name,password and list of roles
//				true ,true, credentialsNonExpired, true,       //set fileds 
			AuthorityUtils.createAuthorityList(roles));                   //<GrantedAuthority>

		return user;
	}
	
	


}
