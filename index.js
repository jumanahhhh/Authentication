// AUTHENTICATION -- COOKIES JWT AND BCRYPT - code written in notes

const express = require("express");
const app = express();
const path = require('path');
const bcrypt = require('bcrypt');
const userModel = require("./models/user");
const postModel = require("./models/post");
const cookieParser = require("cookie-parser");
const jwt = require('jsonwebtoken');

app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get("/", (req, res) => {
    res.render("index");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/profile", isLoggedIn, async (req,res)=>{    
    let user = await userModel.findOne({email: req.user.email});
    // console.log(user);
    res.render("profile", {user});
});

app.post("/register", async (req, res) => {
    let { email, password, name, username, age } = req.body;

    let existingUser = await userModel.findOne({ email });
    if (existingUser) return res.status(500).send("User already exists!");

    // For hashing the password / Securing it
    bcrypt.genSalt(10, (err, salt) => {
        if (err) return res.status(500).send(err);
        
        bcrypt.hash(password, salt, async (err, hash) => {
            if (err) return res.status(500).send(err);

            let userCreated = await userModel.create({
                username,
                name,
                email,
                password: hash,
                age
            });

            // for COOKIES
            let token = jwt.sign({ email: email, userid: userCreated._id }, "shhh");
            res.cookie("token", token);
            res.send("Registered");
        });
    });
});

app.post("/login", async (req, res) => {
    let { email, password } = req.body;

    let existingUser = await userModel.findOne({ email });
    if (!existingUser) return res.status(500).send("Something went wrong!");

    bcrypt.compare(password, existingUser.password, (err, result) => {
        if (result) {
            let token = jwt.sign({ email: email, userid: existingUser._id }, "shhh");
            res.cookie("token", token);
            // res.status(200).send("You can login");
            res.redirect("/profile");
        } else {
            res.redirect("/login");
        }
    });
});

app.get("/logout", (req, res) => {
    res.cookie("token", "");
    res.redirect("/login");
});

// Middleware for protected routes
function isLoggedIn(req, res, next) {
    // if (!req.cookies.token) return res.send("You need to be logged in first");
    if(req.cookies.token === "") res.redirect("/login");

    try {
        let data = jwt.verify(req.cookies.token, "shhh");
        req.user = data;
        next();
    } catch (error) {
        return res.send("You need to be logged in first");
    }
}
app.post("/post", isLoggedIn, async (req, res) => {
    let { content } = req.body;
    if (!content) return res.status(400).send("Content is required");

    let user = await userModel.findOne({ email: req.user.email });
    if (!user) return res.status(404).send("User not found");

    let post = await postModel.create({
        user: user._id,
        content
    });

    user.posts.push(post._id);
    await user.save();

    res.redirect("/profile");
});


app.listen(3000, () => {
    console.log("Server Up!");
});
