const { required } = require('joi');
const { verify } = require('jsonwebtoken');
const mongoose = require('mongoose');

const userSchema = mongoose.Schema({
    email: {
        type: String,
        required: [true, "Email is required"],
        trim: true,
        unique: [true, 'Email must be unique'],
        minLength: [5, 'Email must have minimum 5 characters'],
        lowercase: true
    },

    password: {
        type: String,
        required: [true, "Password is required"],
        trim: true,
        select: false,
    },
    verified: {
        type: String,
        select: false,
    },
    verificationCode: {
        type: String,
        select: false,
        },
    verificationCodeValidation: {
        type: Number,
        select: false,
        },
    forgotPasswordCode: {
        type: String,
        select: false,
        },
    forgotPasswordCodeValidation: {
        type: Number,
        select: false,
        },  
},{
    timestamps: true
})
const User = mongoose.model('User', userSchema);
module.exports = User;
