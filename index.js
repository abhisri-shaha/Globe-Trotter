import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

let currentUserId;
let users = [];

async function getFirstUser(req) {
  const result = await db.query("SELECT id FROM users WHERE account_id = $1 ORDER BY id ASC;", [req.user.id]);
  return result.rows.length ? result.rows[0].id : null;
}

async function markVisited(req) {
  const result = await db.query("SELECT country_code FROM visited_countries WHERE user_id = $1 AND account_id = $2;", [currentUserId, req.user.id]);
  let countries = [];
  result.rows.forEach((country) => {
    countries.push(country.country_code);
  });
  return countries;
}

async function getCurrentUser(req) {
  const result = await db.query("SELECT * FROM users WHERE account_id = $1 ORDER BY id ASC;", [req.user.id]);
  users = result.rows;
  return users.find((user) => user.id == currentUserId);
}

app.get("/", (req, res) => {
  res.render("login.ejs");
});

app.post("/login", (req, res, next) => {
  passport.authenticate("local", async (err, user, info) => {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.render("login.ejs", { error: info.message });
    }
    req.login(user, async (err) => {
      if (err) {
        return next(err);
      }
      currentUserId = await getFirstUser(req);
      if (!currentUserId) {
        return res.redirect("/firstuser");
      }
      return res.redirect("/family");
    });
  })(req, res, next);
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/family", (req, res, next) => {
  passport.authenticate("google", async (err, user, info) => {
    if (err) {
      return next(err);
    }
    req.login(user, async (err) => {
      if (err) {
        return next(err);
      }
      currentUserId = await getFirstUser(req);
      if (!currentUserId || info && info.new) {
        return res.redirect("/firstuser");
      }
      return res.redirect("/family");
    });
  })(req, res, next);
});

app.get("/signup", (req, res) => {
  res.render("signup.ejs");
});

app.post("/signup", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM accounts WHERE username = $1", [username]);
    if (checkResult.rows.length > 0) {
      res.render("signup.ejs", { error: "Account already exists." });
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query("INSERT INTO accounts (username, password) VALUES ($1, $2) RETURNING *", [username, hash]);
          const account = result.rows[0];
          req.login(account, (err) => {
            res.redirect("/firstuser");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.get("/firstuser", (req, res) => {
  res.render("update.ejs", { formAction: "/new", buttonAction: "Add" });
})

app.get("/family", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const currentUser = await getCurrentUser(req);
      const countries = await markVisited(req);
      res.render("family.ejs", {
        countries: countries,
        total: countries.length,
        users: users,
        color: currentUser ? currentUser.color : "transparent",
        error: users.length ? null : "No family members added yet."
      });
    } catch (err) {
      console.error(err);
      res.render("family.ejs", { error: "Error fetching data" });
    }
  } else {
    res.redirect("/");
  }
});

app.post("/addcountry", async (req, res) => {
  const input = req.body["country"];
  const currentUser = await getCurrentUser(req);
  try {
    const result = await db.query("SELECT country_code FROM countries WHERE LOWER(country_name) LIKE '%' || $1 || '%';", [input.toLowerCase()]);
    const countryCode = result.rows[0].country_code;
    try {
      await db.query("INSERT INTO visited_countries (country_code, user_id, account_id) VALUES ($1, $2, $3)", [countryCode, currentUserId, req.user.id]);
      res.redirect("/family");
    } catch (err) {
      console.log(err);
      const country_codes = await markVisited(req);
      res.render("family.ejs", { countryError: "Country is already added, try again", countries: country_codes, total: country_codes.length, users: users, color: currentUser.color });
    }
  } catch (err) {
    console.log(err);
    const country_codes = await markVisited(req);
    res.render("family.ejs", { countryError: "Country does not exist, try again", countries: country_codes, total: country_codes.length, users: users, color: currentUser.color });
  }
});

app.post("/deletecountry", async (req, res) => {
  const input = req.body.country;
  const currentUser = await getCurrentUser(req);
  try {
    const result = await db.query("SELECT country_code FROM countries WHERE LOWER(country_name) LIKE '%' || $1 || '%'", [input.toLowerCase()]);
    const countryCode = result.rows[0].country_code;
    const deleteResult = await db.query("DELETE FROM visited_countries WHERE country_code = $1 AND user_id = $2 AND account_id = $3", [countryCode, currentUserId, req.user.id]);
    if (deleteResult.rowCount !== 0) {
      res.redirect("/family");
    } else {
      const country_codes = await markVisited(req);
      res.render("family.ejs", { countryError: "Country is not added, try again", countries: country_codes, total: country_codes.length, users: users, color: currentUser.color });
    }
  } catch (err) {
    console.log(err);
    const country_codes = await markVisited(req);
    res.render("family.ejs", { countryError: "Country does not exist, try again", countries: country_codes, total: country_codes.length, users: users, color: currentUser.color });
  }
});

app.post("/user", async (req, res) => {
  if (req.body.add === "new") {
    res.redirect("/firstuser");
  } else {
    currentUserId = req.body.user;
    res.redirect("/family");
  }
});

app.post("/new", async (req, res) => {
  const name = req.body.name;
  const color = req.body.color;
  const result = await db.query("INSERT INTO users (account_id, name, color) VALUES ($1, $2, $3) RETURNING *;", [req.user.id, name, color]);
  const id = result.rows[0].id;
  currentUserId = id;
  res.redirect("/family");
});

app.post("/deleteuser", async (req, res) => {
  const deleteUserId = req.body.deleteUserId;
  try {
    await db.query("DELETE FROM visited_countries WHERE user_id = $1 AND account_id = $2;", [deleteUserId, req.user.id]);
    await db.query("DELETE FROM users WHERE id = $1 AND account_id = $2;", [deleteUserId, req.user.id]);
    const usersRemaining = await db.query("SELECT * FROM users WHERE account_id = $1 ORDER BY id ASC;", [req.user.id]);
    if (usersRemaining.rowCount != 0) {
      currentUserId = usersRemaining.rows[0].id;
      res.redirect("/family");
    } else {
      res.redirect("/firstuser");
    }
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).send("Error deleting user.");
  }
});

app.post("/editinguser", async (req, res) => {
  
  if (req.body.editUserColorId) {
    const userId = req.body.editUserColorId;
    const result = await db.query("SELECT color FROM users WHERE id = $1 AND account_id = $2;", [userId, req.user.id]);
    const color = result.rows[0].color;
    res.render("update.ejs", { formAction: "/editusercolor", buttonAction: "Edit", userId: userId, color: color });
  } else {
    const userId = req.body.editUserNameId;
    res.render("update.ejs", { formAction: "/editusername", buttonAction: "Edit", userId: userId});
  }
  
});

app.post("/editusername", async (req, res) => {
  const userId = req.body.userId;
  const newName = req.body.name;
  await db.query("UPDATE users SET name = $1 WHERE id = $2 AND account_id = $3;", [newName, userId, req.user.id]);
  currentUserId = userId;
  res.redirect("/family");
});

app.post("/editusercolor", async (req, res) => {
  const userId = req.body.userId;
  const newColor = req.body.color;
  await db.query("UPDATE users SET color = $1 WHERE id = $2 AND account_id = $3;", [newColor, userId, req.user.id]);
  currentUserId = userId;
  res.redirect("/family");
});

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    // req.session.destroy((err) => {
    //   if (err) {
    //     return next(err);
    //   }
    //   res.clearCookie("user_session"); // clear session on logout
      res.redirect("/"); // Redirect to home or login page
    // });
  });
});

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const result = await db.query("SELECT * FROM accounts WHERE username = $1;", [username]);
      const account = result.rows[0];
      if (!account) {
        return done(null, false, { message: "Account does not exist" });
      }
      bcrypt.compare(password, account.password, (err, res) => {
        if (res) {
          return done(null, account);
        } else {
          return done(null, false, { message: "Incorrect password" });
        }
      });
    } catch (err) {
      return done(err);
    }
  })
);

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/family",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const result = await db.query("SELECT * FROM accounts WHERE username = $1;", [profile.emails[0].value]);
        let account = result.rows[0];
        if (!account) {
          const newAccount = await db.query("INSERT INTO accounts (username, password) VALUES ($1, $2) RETURNING *;", [profile.emails[0].value, "google"]);
          account = newAccount.rows[0];
          return done(null, account, { new: true });
        }
        return done(null, account);
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
})

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
