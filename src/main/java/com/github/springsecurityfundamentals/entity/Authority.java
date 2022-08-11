package com.github.springsecurityfundamentals.entity;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.ForeignKey;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;
import java.util.ArrayList;
import java.util.List;

@NoArgsConstructor
@Getter
@Setter

@Entity
@Table(name = "authorities")
public class Authority {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "authorities_sequence_generator")
    @SequenceGenerator(name = "authorities_sequence_generator", sequenceName = "authorities_sequence", allocationSize = 1)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @Setter(AccessLevel.PRIVATE)
    @ManyToMany
    @JoinTable(name = "user_authorities",
            joinColumns = @JoinColumn(name = "user_id", foreignKey = @ForeignKey(name = "user_authorities_user_id_fk")),
            inverseJoinColumns = @JoinColumn(name = "authority_id", foreignKey = @ForeignKey(name = "user_authorities_authority_id_fk")))
    public List<User> users = new ArrayList<>();

    public Authority(String name, List<User> users) {
        this.name = name;
        this.users = users;
    }

    public void setUser(User user) {
        user.getAuthorities().add(this);
        users.add(user);
    }

}