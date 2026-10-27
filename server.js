const express = require('express')
const bcrypt = require('bcrypt');
const saltRounds = 10;
const {prisma} = require("./config.js")

const app = express()
app.use(express.json());


app.get("/",(req,res)=>{
    res.json("HEllo world ")
    console.log("this is the get / route ")
})


app.post("/signup",async(req,res)=>{
    const {username,password}=req.body || {};
    if( typeof username !== "string" || 
        !username.trim()|| 
        typeof password !== "string" || 
        !password.trim())
        return res.status(401).json({
            "message" : "User name & password should be valid "
        })
    try{
        const hash = await bcrypt.hash(password.trim(), saltRounds);
        const user = await prisma.user.create({
            data : {
                username: username.trim(),
                password: hash,
            },
        })

        res.status(201).json(user)
    }
    catch(err){
        console.log(err);
        return res.status(500).send();
    }
})

app.post("/login",async(req,res)=>{
    const {username,password}=req.body || {};
    if( typeof username !== "string" || 
        !username.trim()|| 
        typeof password !== "string" || 
        !password.trim())
        return res.status(401).json({
            "message" : "User name & password should be valid "
        })
    try{
        const user = await prisma.user.findUnique({
            where : {
                username : username.trim()
            }
        })
        if (!user) return res.status(404).json({message:"User not found"})
        const result =await bcrypt.compare(password, user.password)
        if (!result) return  res.json({message : "invalid credentials"})
        res.send(`Welcome ${user.username}`)
        
    }catch(err){
        console.error(err);
        
        return res.status(500).json({
        message: "Internal server error"
});
    }
})






app.listen(3000,()=>{
    console.log("Express running in 3000")
})