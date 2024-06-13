import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt"
import passport from "passport";
import session from "express-session";
import { Strategy } from "passport-local";
import 'dotenv/config';

const app = express();
const port = 3000;
const saltRounds = 10;


app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static('public'));

app.use(session({
    secret:"TOPSECRET",
    resave: false,
    saveUninitialized:true,
    cookie :{
        maxAge : 1000*60*5
    }
}));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD
});
db.connect();

app.get("/",(req,res)=>{
    res.render("home.ejs")
})

app.get("/login",(req,res)=>{
    res.render("login.ejs")
})
app.get("/register",(req,res)=>{
    res.render("register.ejs")
})
app.get("/secrets",(req,res)=>{
   if(req.isAuthenticated()){
    res.render("secrets.ejs");
   }else{
    res.redirect("/login")
   }
})


app.post("/register", async(req,res)=>{
    const email = req.body.username;
    const password = req.body.password;

    try {
        const checkResult = await db.query("SELECT * FROM users WHERE email=$1",[email,]);

        if(checkResult.rows.length>0){
            res.send("Email already exist. try log in")
        }else{
            //hashing the pass
            bcrypt.hash(password, saltRounds, async(err,hash)=>{
                if(err){
                    console.log("Error hashing password "+ err)
                }else{
                  const result= await db.query("INSERT INTO users (email, password) VALUES($1, $2) RETURNING *",[email, hash]);
                  const user = result.rows[0];
                  req.login(user, (err)=>{
                    console.log(err);
                    res.redirect("/secrets")
                  })
                   
                }
            })
        }
    } catch (error) {
        console.log(error);
        
    }
})

app.post("/login",passport.authenticate('local',{
    successRedirect:'/secrets',
    failureRedirect:"/login"
}));


passport.use(new Strategy(async function verify(username, password, cb){
      try {
        const result = await db.query("SELECT * FROM users WHERE email=$1 ",[username]);

        if(result.rows.length>0){
            const user = result.rows[0];

            const storedPassword = user.password;

            bcrypt.compare(password, storedPassword, (err, result)=>{
                if(err){
                    return cb(err)
                }else{
                    if(result){
                        return cb(null, user);
                    }else{
                        return cb(null, false)
                    }
                }
            });

        }else{
            return cb("User not found")
        }
      } catch (error) {
         return cb(error)
      }
}))


passport.serializeUser((user,cb)=>{
    cb(null, user);
})
passport.deserializeUser((user,cb)=>{
    cb(null, user);
})


app.listen(port,()=>{
    console.log(`Server is running on port ${port}`);
})