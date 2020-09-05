package telran.ashkelon2020.accounting.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import telran.ashkelon2020.forum.dao.PostRepository;
import telran.ashkelon2020.forum.model.Post;

@Service("customSecurity")
public class CustomWebSecurityService {

	@Autowired
	PostRepository postRepository;

	public boolean checkPostAuthority(String id, String user) {
		Post post = postRepository.findById(id).orElse(null);
		return post==null ? true : post.getAuthor().equals(user);
	}

}
