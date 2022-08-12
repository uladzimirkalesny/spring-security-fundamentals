INSERT INTO users(id, username, password)
VALUES (1, 'Uladzimir', '123');
INSERT INTO authorities(id, name)
VALUES (1, 'read');
INSERT INTO user_authorities(user_id, authority_id)
VALUES (1, 1);