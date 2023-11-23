package saaspe.security.serviceImpl;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import saaspe.security.entity.UserLoginDetails;
import saaspe.security.repository.UserLoginDetailsRepository;
import saaspe.security.service.UserLoginService;

@Service
public class UserLoginServiceImpl implements UserLoginService {

	@Autowired
	private UserLoginDetailsRepository userLoginDetailsRepository;

	@Override
	@Transactional
	public Optional<UserLoginDetails> loadUserByUsername(String username) throws UsernameNotFoundException {
		return userLoginDetailsRepository.findById(username);
	}
}