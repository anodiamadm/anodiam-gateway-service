package com.anodiam.gateway.data.service;

import com.anodiam.gateway.data.model.AnodiamUser;
import com.anodiam.gateway.data.repository.AnodiamUserRepository;
import org.springframework.stereotype.Service;

@Service
public class AnodiamUserService {
    private final AnodiamUserRepository anodiamUserRepository;

    public AnodiamUserService(AnodiamUserRepository anodiamUserRepository) {
        this.anodiamUserRepository = anodiamUserRepository;
    }

    public AnodiamUser saveOrGet(AnodiamUser anodiamUser) {
        if(this.anodiamUserRepository.existsByEmailAndProvider(anodiamUser.getEmail(), anodiamUser.getProvider())) {
            return this.anodiamUserRepository.findByEmailAndProvider(anodiamUser.getEmail(), anodiamUser.getProvider()).get();
        } else {
            return this.anodiamUserRepository.save(anodiamUser);
        }
    }
}
