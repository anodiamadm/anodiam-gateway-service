package com.anodiam.gateway.data.model;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "anodiam_users",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = {"email", "provider"})
        })
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class AnodiamUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Size(max = 50)
    @Email
    private String email;

    @NotBlank
    @Size(max = 10)
    private String provider;

    @ManyToMany(fetch = FetchType.EAGER)
    private Set<Role> roles = new HashSet<>();

}
