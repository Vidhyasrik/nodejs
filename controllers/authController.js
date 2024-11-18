const { signupSchema, 
       signinSchema, 
       sendVerificationCodeSchema, 
       acceptedCodeSchema,
       changePasswordSchema,
       acceptedFPCodeSchema
      } = require("../middlewares/validator");
const jwt = require('jsonwebtoken');
const { doHash, doHashValidation } = require("../utils/hashing");
const User = require('../models/usersModel');
const transport = require('../middlewares/sendMail')
const { exist } = require("joi");
exports.signup = async (req, res) => {
    const {email, password} = req.body;
    try{
        const {error, value} = signupSchema.validate({email, password});
        if(error){
            return res.status(401).json({success: false, message: error.details[0].message});
        }
        const existingUser = await User.findOne({email});
        if(existingUser){
            res.status(401).json({success: false, message: "Email already exists"})
        }
        const hashedPassword = await doHash( password, 12);
        const newUser = new User({
            email,
            password: hashedPassword
        })
        const result = await newUser.save();
        result.password = undefined;
        return res.status(201).json({success: true, message: "User created successfully",result});
    }catch(error){
        console.log(error)
    }
};

exports.signin = async (req, res) => {
    const {email, password} = req.body;
    try{
        const {error, value} = signinSchema.validate({email, password});
        if(error){
            return res.status(401).json({success: false, message: error.details[0].message});
        }
        const existingUser = await User.findOne({email}).select('+password');
        if(!existingUser){
            res.status(401).json({success: false, message: "User does not exists!"})
        }
        const result = await doHashValidation(password, existingUser.password);
        if(!result){
            return res.status(401).json({success: false, message: "Invalid password!"})
        }
        const token = jwt.sign({
            userId: existingUser._id,
            email: existingUser.email,
            verified: existingUser.verified
        },
        process.env.TOKEN_SECRET,
        { expiresIn: '8h' }
    );
    res.cookie('Authorization', 
        'Bearer ' + token, 
        {expires: new Date(Date.now()+8*3600000), 
            httpOnly: process.env.NODE_ENV === 'production',
            secure: process.env.NODE_ENV === 'production'
        }
    ).json({
        success: true,
        message: "User logged in successfully",
        token
    })
        return res.status(201).json({success: true, message: "User created successfully",result});
    }catch(error){
        console.log(error)
    }
};

exports.signout = async (req, res) => {
    res.clearCookie('Authorization').status(200).json({success: true, message: "User logged out successfully"})
}

exports.sendVerificationCode = async (req, res) => {
    const {email} = req.body;
    try{
        const {error, value} = sendVerificationCodeSchema.validate({email});
        if(error){
            return res.status(401).json({success: false, message: error.details[0].message});
        }
        const existingUser = await User.findOne({email})
        // .select('+password');
        if(!existingUser){
            return res.status(401).json({success: false, message: "User does not exists"});
        }

        if(existingUser.verified){
            return res.status(401).json({success: false, message: "User is already verified"});
        }
        const codeValue = Math.floor(100000 + Math.random() * 900000).toString();
        let info = await transport.sendMail({
            from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
            to: existingUser.email,
            subject: "Verification Code",
            html: `<p>Verification Code: ${codeValue}</p>`,
        })
        if(info.accepted[0] === existingUser.email){
            const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);
            existingUser.verificationCode = hashedCodeValue;
            existingUser.verificationCodeValidation = Date.now();
            await existingUser.save();
            return res.status(201).json({success: true, message: "Verification code sent successfully"});
        }
res.status(401).json({success: false, message: 'code sent failed'});
} catch(error){
    console.log(error)
}}

exports.verifyVerificationCode = async (req, res) => {
    const {email, providedCode} = req.body;
    try{
        const {error, value} = acceptedCodeSchema.validate({email, providedCode});
        if(error){
            return res.status(401).json({success: false, message: error.details[0].message});
        }
        const codeValue = providedCode.toString();
        const existingUser = await User.findOne({email}).select('+verificationCode +verificationCodeValidation');
        if(!existingUser){
            return res.status(401).json({success: false, message: "User does not exists"});
        }
        if(existingUser.verified){
            return res.status(401).json({success: false, message: "User is already verified"});
        }
        if(!existingUser.verificationCode || !existingUser.verificationCodeValidation){
            return res.status(401).json({success: false, message: "Something is wrong with code!"});
        }
        if(Date.now() - existingUser.verificationCodeValidation>5*60*1000){
            return res.status(401).json({success: false, message: "Verification code is expired"});
        }
        const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);
        if(hashedCodeValue !== existingUser.verificationCode){
            return res.status(401).json({success: false, message: "Verification code is incorrect"})
        }
        existingUser.verified = true;
        existingUser.verificationCode = undefined;
        existingUser.verificationCodeValidation = undefined;
        await existingUser.save();
        return res.status(201).json({success: true, message: "Account has been verified Successfully"})
    }catch(error){
        console.log(error)
    }
}

exports.changePassword = async (req, res) => {
    const {userId, verified} = req.user;
    const {oldPassword, newPassword} = req.body;
    try {
        const {error, value} = changePasswordSchema.validate({oldPassword, newPassword});
        if(error){
            return res.status(401).json({success: false, message: error.details[0].message});
        }
        if(!verified){
            return res.status(401).json({success: false, message: "Account is not verified"});
        }
        const existingUser = await User.findById({_id: userId}).select('+password');
        if(!existingUser){
            return res.status(401).json({success: false, message: "User does not exists"});
        }
        const result = await doHashValidation(oldPassword, existingUser.password);
        if(!result){
            return res.status(401).json({success: false, message: "Old password is incorrect"});
        }
        const hashedPassword = await doHash(newPassword, 12);
        existingUser.password = hashedPassword;
        await existingUser.save();
        return res.status(200).json({success: true, message: 'Password updated Successfully!!'})
    } catch (error) {
        console.log(error)
        
    }
}

exports.sendForgotPasswordCode = async (req, res) => {
    const {email} = req.body;
    try{
        const existingUser = await User.findOne({email});
        if(!existingUser){
            return res.status(401).json({success: false, message: "User does not exists"});
        }
        const codeValue = Math.floor(Math.random() * 1000000).toString();
        let info = await transport.sendMail({
			from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
			to: existingUser.email,
			subject: 'Forgot password code',
			html: '<h1>' + codeValue + '</h1>',
		});
        if (info.accepted[0] === existingUser.email) {
			const hashedCodeValue = hmacProcess(
				codeValue,
				process.env.HMAC_VERIFICATION_CODE_SECRET
			);
			existingUser.forgotPasswordCode = hashedCodeValue;
			existingUser.forgotPasswordCodeValidation = Date.now();
			await existingUser.save();
			return res.status(200).json({ success: true, message: 'Code sent!' });
		}
		res.status(400).json({ success: false, message: 'Code sent failed!' });

    }catch(error){
        console.log(error)
    }
};

exports.verifyForgotPasswordCode = async (req, res) => {
    const { email, providedCode, newPassword } = req.body;
    try{
        const {error, value} = acceptedFPCodeSchema.validate({
            email,
            providedCode,
            newPassword
        });
        if(error){
            return res.status(400).json({success: false, message: error.details[0].message});
        }
        const codeValue = providedCode;
        const existingUser = await User.findOne({ email }).select(
			'+forgotPasswordCode +forgotPasswordCodeValidation'
		);

        if (!existingUser) {
			return res
				.status(401)
				.json({ success: false, message: 'User does not exists!' });
		}

        if (
			!existingUser.forgotPasswordCode ||
			!existingUser.forgotPasswordCodeValidation
		) {
			return res
				.status(400)
				.json({ success: false, message: 'something is wrong with the code!' });
		}

        if (
			Date.now() - existingUser.forgotPasswordCodeValidation >
			5 * 60 * 1000
		) {
			return res
				.status(400)
				.json({ success: false, message: 'code has been expired!' });
		}

        const hashedCodeValue = hmacProcess(
			codeValue,
			process.env.HMAC_VERIFICATION_CODE_SECRET
		);

		if (hashedCodeValue === existingUser.forgotPasswordCode) {
			const hashedPassword = await doHash(newPassword, 12);
			existingUser.password = hashedPassword;
			existingUser.forgotPasswordCode = undefined;
			existingUser.forgotPasswordCodeValidation = undefined;
			await existingUser.save();
			return res
				.status(200)
				.json({ success: true, message: 'Password updated!!' });
		}
		return res
			.status(400)
			.json({ success: false, message: 'unexpected occured!!' });

    }catch(error){
        console.log(error)
    }
};