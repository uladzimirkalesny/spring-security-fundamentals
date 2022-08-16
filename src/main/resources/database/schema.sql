CREATE SEQUENCE authorities_sequence START WITH 1 INCREMENT BY 1;

CREATE SEQUENCE users_sequence START WITH 1 INCREMENT BY 1;

CREATE TABLE authorities
(
    id   BIGINT       NOT NULL,
    name VARCHAR(255) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE user_authorities
(
    user_id      BIGINT NOT NULL,
    authority_id BIGINT NOT NULL
);

CREATE TABLE users
(
    id       BIGINT       NOT NULL,
    password VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    PRIMARY KEY (id)
);

ALTER TABLE authorities
    ADD CONSTRAINT uk_nb3atvjf9ov5d0egnuk47o5e UNIQUE (name);

ALTER TABLE users
    ADD CONSTRAINT uk_r43af9ap4edm43mmtq01oddj6 UNIQUE (username);

ALTER TABLE user_authorities
    ADD CONSTRAINT user_authorities_authority_id_fk FOREIGN KEY (authority_id) REFERENCES users;

ALTER TABLE user_authorities
    ADD CONSTRAINT user_authorities_user_id_fk FOREIGN KEY (user_id) REFERENCES authorities;