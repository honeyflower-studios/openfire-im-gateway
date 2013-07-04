# Encoded OAuth token does not fit in password field
alter table ofGatewayRegistration modify column password varchar(1024) default null;

# Update database version
UPDATE ofVersion SET version = 12 WHERE name = 'gateway';