const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const authRouter = require('./routers/authRouter');
const postsRouter = require('./routers/postsRouter');
mongoose.connect(process.env.MONGO_URI).then(()=>{
    console.log("Database Connected...")
}).catch((err)=>{
    console.log(err);
})
const app = express()
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use('/api/auth', authRouter);
app.use('/api/posts', postsRouter);
app.use(cors())
app.use(helmet())
app.use(cookieParser())
app.use(express.json())
app.use(express.urlencoded({extended: true}))
app.get('/', (req,res)=>{
    res.json({message: "Hello from the Server...."})
})

app.listen(process.env.PORT, ()=>{
    console.log(`Server is running on port ${process.env.PORT}`)
})