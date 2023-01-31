package com.mopstream.back.repository;
import java.util.Optional;

import com.mopstream.back.models.Role;
import com.mopstream.back.models.ERole;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}