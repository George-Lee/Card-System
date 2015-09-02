drop table if exists cards;
create table cards (
	id integer primary key autoincrement,
	name text not null,
	cvc text not null,
	cardNumber text not null,
	expireDate text not null,
	referenceCode text not null,
	amount text not null,
	user text not null
);
drop table if exists password;
create table password(
	id integer primary key autoincrement,
	password text not null
);
drop table if exists users;
create table users(
	id integer primary key autoincrement,
	username text not null,
	password text not null,
	reset int not null
);
drop table if exists expiration;
create table expiration(
	id integer primary key autoincrement,
	start integer not null,
	end integer not null
);