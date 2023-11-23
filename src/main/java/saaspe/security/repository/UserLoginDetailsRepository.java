package saaspe.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import saaspe.security.entity.UserLoginDetails;

public interface UserLoginDetailsRepository extends JpaRepository<UserLoginDetails, String> {

}
