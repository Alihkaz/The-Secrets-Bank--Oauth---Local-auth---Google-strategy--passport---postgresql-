// 

import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = process.env.ROUND;
env.config();



app.use(
  session({
    secret: process.env.SESSION_SECRET, //to save the session and status of login to the db
    resave: false, //force session to be saved in the store
    saveUninitialized: true,
    cookie:{ //duration of the session
      maxage :1000*60*60*24
     }
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




app.get("/", (req, res) => {
  res.render("home.ejs");
});




app.get("/login", (req, res) => {
  res.render("login.ejs");
});






app.get("/register", (req, res) => {
  res.render("register.ejs");
});






app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});







// if the login page has authenticated the user , then redirect him
// to secrets , if not authenticated and try to access the route directly , then we will obey himto login and block access !  
app.get("/secrets", async (req, res) => {


  if (req.isAuthenticated()) {
    try{

      const checkResult = await db.query("SELECT * FROM users WHERE email = $1",[req.user.email])
      let secret=checkResult.rows[0].secret;
      if (secret) {res.render("secrets.ejs", { secret: secret });}
      else {res.render("secrets.ejs", { secret: "Jack Bauer is my hero." });} 
    }

    catch (err) {
      console.log(err);
    }

  }
  
  else {
    res.redirect("/login");
  }
});










app.get("/submit", (req, res) => {

  if (req.isAuthenticated()) {res.render("submit.ejs");} 
  
  else {res.redirect("/login");}

});









app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);







app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);







// when the user hits the login route , we will use the passport strategy and function to login! 
// if the stratge results in success wewill redirect him to secrets , not to login again with different credentials
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);









// when the user egisters , we will get the data of the user
// by sql RETURNING  method , and we are saving the data we get back 
// in the user variable that we will use to serialize and save it inside the cookie ! 
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
       //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});














// submiting the secret when the user hits submit in the submit.ejs
app.post("/submit", async (req, res) => {
  const secret = req.body.secret;
  

  if (req.isAuthenticated()) {
    
    try{
      await db.query(`UPDATE users SET secret = $1 WHERE email = $2`, [submittedSecret, req.user.email,]);
      res.redirect("/secrets");
       }
    

    catch (err) {console.log(err); }

    }
  
  else {res.redirect("/login");}

});


















// locall Authentication strategy
// the passport startegy which uses the email and password to authenticate
// and extracts the user data to save them in a cookie and store them 
// in the local storage using the serializer , and the nuser data will be used to check if the user is authenticated or not ! 
// the strategy will use the email and username sended by the form , and bcrypt to autherize after hashing ! 
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user); //returning the data related to the user so we can access it in another routes , its very important 
                                      //  in addition to sending the user data as a form of cookie 
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);








// note on how this works:
// when the user clicks on sign up with google , we hit the get google auth route
// that route will call the function below , giving it the user profile who wants to sign in
// and then using the data of that profile , we insert the email and the username of 
// the user to our database and check for any err
// in another time he wants to login , we use this startegy to check for any error with google account ,
// rather then just checking if he is registered in our database , if its success , then we redirrect
// him to secrets page , failure we redirect him to login page to login again ! 


// google strategy (using OAuth )
passport.use( "google",
  new GoogleStrategy(

     // parameters we pass to passport while using OAuth , we saved them in .env file
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },

     // asyncronynse function
    async (accessToken, refreshToken, profile, cb) => { //refresh token is for saving sessions 


      try {
        console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);


        if (result.rows.length === 0) {//if the user is not availbale before in our database
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)", //then register him with his email we get from prfile array ,and the password her is not inserted , instead we insert google
            [profile.email, "google"]
          );
       return cb(null, newUser.rows[0]); //when every thing is okay ,returning the data related to the user so we can access
           
                                    //  it in another routes , its very important  in addition to sending the user data as a form of cookie 
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);





// saving the data entered by the user in a local storage 
// i.e when he post the credentails , we get them , put them in a cookie , then send that 
// cookie in a response to be stored in the local storage of the response !
passport.serializeUser((user, cb) => {
  cb(null, user);
});








// when the user want to access his website again , 
// we process the cookie that have the saved credentails
// hold it and log him back in the seeion 
passport.deserializeUser((user, cb) => {
  cb(null, user);
});






app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});









// ALTER TABLE users ADD COLUMN secret TEXT;
