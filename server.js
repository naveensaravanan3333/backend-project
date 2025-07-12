const express=require('express')
const db=require('better-sqlite3')('ourApp.db')
db.pragma('journal_mode = WAL')
const bcrypt=require('bcrypt')
const jwt=require('jsonwebtoken')
const cookieParser=require('cookie-parser')
require('dotenv').config()
const sanitizeHTML=require('sanitize-html')
const {marked}=require('marked')
const app=express()

//database setup here
const createTables=db.transaction(()=>{
    db.prepare(`
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
    )
    `).run()
  db.prepare(`
  CREATE TABLE IF NOT EXISTS posts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdate TEXT,
    title STRING NOT NULL,
    content STRING NOT NULL,
    authorid INTEGER,
    FOREIGN KEY (authorid) REFERENCES users (id)
  )
  `).run()
})
createTables()  //it will create post in table
//database setup ends here

app.set("view engine","ejs")
app.use(express.urlencoded({extended:false}))
app.use(express.static("public"))
app.use(cookieParser())

app.use(function(req,res,next){

    res.locals.stylish=function(Content){
        return sanitizeHTML(marked.parse(Content),{
            allowedTags:["h1","h2","h3","h4","h5","h6","strong","li","ol","ul","i","p","em"],
            allowedAttributes:{}
        })
    }

    res.locals.errors=[]

    //try to decode incoming cookie
    try{
        const decoded=jwt.verify(req.cookies.MyApp,process.env.JWTSECRET)
        req.user=decoded                            //this will be use in app.post("/edited-post/:id",(req,res)=>{})
    }catch(err){
        req.user=false
    }
    res.locals.user=req.user
    console.log(req.user)
    next()
})

app.get("/",(req,res)=>{
if(req.user){
    const statement=db.prepare("SELECT * FROM posts WHERE authorid=? ORDER BY createdate DESC")
    const post=statement.all(req.user.userid)
    return res.render("dashboard",{posts:post})  //return must
    }
res.render("homepage",{errors:[]})
})
//just only for address the login link
app.get("/login",(req,res)=>{
     res.render("login")
})
app.get("/logout",(req,res)=>{
    res.clearCookie("MyApp")
    res.redirect("/")
})

//stopping create-post link without log in

function mustbeloggedin(req,res,next){
    if(req.user){
        return next()
    }
    return res.redirect("/")
    next()
}
app.get("/create-post",mustbeloggedin,(req,res)=>{
      res.render("create-post")
})
app.get("/post/:id",(req,res)=>{
    const statement=db.prepare("SELECT posts.*,users.username FROM posts INNER JOIN users on posts.authorid=users.id WHERE posts.id =?")
    const post=statement.get(req.params.id)
    if(!post)return res.redirect("/")
   
    res.render("single-post",{post})
})
app.get("/edit-post/:id",(req,res)=>{
    const statement=db.prepare("SELECT * FROM posts WHERE id=?")
    const post=statement.get(req.params.id)
    if(post.authorid!==req.user.userid){
        return res.redirect("/")
    }
    const error=[]
    if(error.length){
        return res.render("/")
    }
    res.render("edit-post",{post})
})
app.get("/delete-post/:id",(req,res)=>{
    const statement=db.prepare("SELECT * FROM posts WHERE id=?")
    const post=statement.get(req.params.id)
    if(!post || post.authorid!==req.user.userid){
        return res.redirect("/")
    }
    res.render("delete-post",{post,error:[]})
})

app.post("/register",(req,res)=>{
    const errors=[]
    if(typeof req.body.username!=="string")req.body.username=""
    if(typeof req.body.password!=="string")req.body.password=""
    
    req.body.username=req.body.username?.trim()  || ""
 
    if(!req.body.username)errors.push("You must provide username")
    if(req.body.username && req.body.username.length<3)errors.push("username must be at least 3 characters")
    if(req.body.username && req.body.username.length>15)errors.push("Username can't exceed 15 characters") 
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/))errors.push("username can only contain letters and numbers")

    if(!req.body.password)errors.push("You must provide password")
    if(req.body.password && req.body.password.length<12)errors.push("password must be at least 12 characters")
    if(req.body.password && req.body.password.length>20)errors.push("password can not exceed 20 characters") 

    if(errors.length)
        return res.render("homepage")

// save the new user into the data
//bcrypt is to convert the password into hah type
    const salt=bcrypt.genSaltSync(10)
    req.body.password=bcrypt.hashSync(req.body.password,salt)
    
    const ourStatement=db.prepare("INSERT INTO users (username,password) VALUES (?,?)")
    const lookupStatement=db.prepare("SELECT * FROM users WHERE ROWID=?")
    let ourUser
    try {
    const result=ourStatement.run(req.body.username, req.body.password)
    ourUser=lookupStatement.get(result.lastInsertRowid)
} catch (e) {
    if (e.message.includes("UNIQUE constraint failed")) {
        errors.push("This username is already taken")
        return res.render("homepage",{errors})
    } else {
        throw e
    }
}
    //log the user by giving them a cookie//
    const ourTokenValue=jwt.sign({exp:Math.floor(Date.now()/1000)+60*60*24, skycolor:"blue",userid:ourUser.id,username:ourUser.username},process.env.JWTSECRET)
    res.cookie("MyApp",ourTokenValue,{
        httpOnly:true,
        secure:true,
        sameSite:"strict",
        maxAge:1000*60*60*24
    })
    res.send("thank you")
})
app.post("/login",(req,res)=>{
    let errors=[]
    if(typeof req.body.username!=="string")req.body.username=""
    if(typeof req.body.password!=="string")req.body.password=""
    
    if(req.body.username?.trim()=="")errors=["Invalid username/password"]
    if(req.body.password=="")errors=["Invalid username/password"]

    if(errors.length){
        return res.render("login",{errors})
    }

    const userInQuestionStatement=db.prepare("SELECT * FROM users WHERE username=?")
    const userInQuestion=userInQuestionStatement.get(req.body.username)

    if(!userInQuestion){
        errors=["Invalid username/password"]
        return res.render("login",{errors})
    }
 
     const matchOrNot=bcrypt.compareSync(req.body.password,userInQuestion.password)
     if(!matchOrNot){
        errors=["Invalid username/password"]
        return res.render("login",{errors})
}

//give them a cookie
//redirect
const ourTokenValue=jwt.sign({exp:Math.floor(Date.now()/1000)+60*60*24, skycolor:"blue",userid:userInQuestion.id,username:userInQuestion.username},process.env.JWTSECRET)
    res.cookie("MyApp",ourTokenValue,{
        httpOnly:true,
        secure:true,
        sameSite:"strict",
        maxAge:1000*60*60*24
    })
    res.redirect("/")
})
function postvalidation(req){
    const errors=[]
    if(typeof req.body.title!=="string")req.body.title=""
    if(typeof req.body.content!=="string")req.body.content=""
    //sanitizing html
    req.body.title=sanitizeHTML(req.body.title.trim(),{allowedTags:[],allowedAttributes:{}})
    req.body.content=sanitizeHTML(req.body.content.trim(),{allowedTags:[],allowedAttributes:{}})
    if(!req.body.title)errors.push("You must provide title")
    if(!req.body.content)errors.push("you must provide content")
    return errors                                                                                  //must 
}
app.post("/create-post",mustbeloggedin,(req,res)=>{
    const errors=postvalidation(req)
    if(errors.length){
        return res.render("create-post",{errors})
    }
    const ourstatement=db.prepare("INSERT INTO posts(title,content,authorid,createdate) VALUES(?,?,?,?)")
    const result=ourstatement.run(req.body.title,req.body.content,req.user.userid,new Date().toISOString())
    const getpoststatement=db.prepare("SELECT * FROM posts WHERE ROWID=?")
    const realpost=getpoststatement.get(result.lastInsertRowid)
    res.redirect(`/post/${realpost.id}`)
})
app.post("/edit-post/:id",mustbeloggedin,(req,res)=>{
    const statement=db.prepare("SELECT * FROM posts WHERE id=?")
    const post=statement.get(req.params.id)
    if(post.authorid!==req.user.userid){
        return res.redirect("/")
    }
    if(!post){
        return res.render("/")
    }
   const errors=postvalidation(req)          //postvalidation is from function postvalidation(req){}
   if(errors.length){
    return res.render("edit-post",{errors})   //return must
   }
   const updatestatement=db.prepare("UPDATE posts SET title=?,content=? WHERE id=?")
   updatestatement.run(req.body.title,req.body.content,req.params.id)
   res.redirect(`/post/${req.params.id}`)
    //redirect instead of render
})
app.post("/delete-post/:id",(req,res)=>{
    const statement=db.prepare("SELECT * FROM posts WHERE id=?")
    const post=statement.get(req.params.id)
    if(!post || post.authorid!==req.user.userid){
        return res.redirect("/")
    }
    const deletestatement=db.prepare("DELETE FROM posts WHERE id=?")
    deletestatement.run(req.params.id)
    return res.redirect("/")
})

app.listen(3304)