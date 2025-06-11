INSERT
IGNORE INTO `users` VALUES ('user', '{noop}Final135Fantasy!', '1');
INSERT
IGNORE INTO `authorities` VALUES ('user', 'read');

INSERT
IGNORE INTO `users` VALUES ('admin', '{bcrypt}$2a$12$F957ZR9njP0.PPlFqs/gj.ShqWZFghUG9mgivPIEr9TN12MOvX0de', '1');
INSERT
IGNORE INTO `authorities` VALUES ('admin', 'admin');


INSERT
IGNORE INTO customers (email, pwd, role)
VALUES ('czen@example.com', '{bcrypt}$2a$10$YE7AvbsVqebpGrcyZWN7sOWhnJtlzn1vEqTyzYDgZx640JEl5zB1u', 'ROLE_USER');

INSERT
IGNORE INTO customers (email, pwd, role)
VALUES ('czen@gmail.com', '{bcrypt}$2a$04$9PkGvvnIpzEAPqXaUKippeqYi0bfJFk29uf1v/BgyGI8foemMRVny', 'ROLE_ADMIN');