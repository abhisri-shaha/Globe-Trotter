
-- Table for accounts
CREATE TABLE accounts (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

-- Table for family members
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    account_id INT REFERENCES accounts(id),
    name TEXT NOT NULL,
    color VARCHAR(20),
    UNIQUE (account_id, id) -- Ensure unique account_id and id pairs
);

-- Table for visited countries
CREATE TABLE visited_countries (
    id SERIAL PRIMARY KEY,
    country_code CHAR(2) NOT NULL,
    user_id INT NOT NULL,
    account_id INT NOT NULL,
    FOREIGN KEY (user_id, account_id) REFERENCES users(id, account_id),
    UNIQUE (user_id, country_code) -- Ensure each country is visited once per user
);