package saaspe.security.service;

import java.util.Optional;

import saaspe.security.entity.UserLoginDetails;

public interface UserLoginService {
	
	Optional<UserLoginDetails> loadUserByUsername(String userName);
}
