package com.anodiam.gateway.data.repository;

import com.anodiam.gateway.data.model.AnodiamUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AnodiamUserRepository extends JpaRepository<AnodiamUser, Long> {
  Optional<AnodiamUser> findByEmailAndProvider(String email, String provider);
  Boolean existsByEmailAndProvider(String email, String provider);

}
