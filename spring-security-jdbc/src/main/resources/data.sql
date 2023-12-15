INSERT INTO users(username,password,enabled)
values ('user','pass',true),
       ('admin','pass',true);

INSERT INTO authorities(username,authority)
values ('user','ROLE_USER'),
       ('admin','ROLE_ADMIN');