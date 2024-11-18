const joi = require('joi');

exports.signupSchema = joi.object({
    email: joi.string()
    .min(6)
    .max(60)
    .required()
    .email({
        tlds: {allow: ['com', 'net']},
    }),
    password: joi.string()
    .required()
    .pattern(new RegExp('^[a-zA-Z0-9._$@]+$'))
    
});

exports.signinSchema = joi.object({
    email: joi.string()
    .min(6)
    .max(60)
    .required()
    .email({
        tlds: {allow: ['com', 'net']},
    }),
    password: joi.string()
    .required()
    .pattern(new RegExp('^[a-zA-Z0-9._$@]+$'))
    
});

exports.sendVerificationCodeSchema = joi.object({
    email: joi.string()
    .min(6)
    .max(60)
    .required()
    .email({
        tlds: {allow: ['com', 'net']},
    })
});

exports.acceptedCodeSchema = joi.object({
    email: joi.string()
    .min(6)
    .max(60)
    .required()
    .email({
        tlds: {allow: ['com', 'net']},
    }),
    providedCode: joi.number().required()
});

exports.changePasswordSchema = joi.object({
    oldPassword: joi.string()
    .required()
    .pattern(new RegExp('^[a-zA-Z0-9._$@]+$')),
    newPassword: joi.string()
    .required()
    .pattern(new RegExp('^[a-zA-Z0-9._$@]+$'))

})

exports.acceptedFPCodeSchema = joi.object({
	email: joi.string()
		.min(6)
		.max(60)
		.required()
		.email({
			tlds: { allow: ['com', 'net'] },
		}),
	providedCode: joi.number().required(),
	newPassword: joi.string()
		.required()
		.pattern(new RegExp('^[a-zA-Z0-9._$@]+$')),
});

exports.createPostSchema = joi.object({
    title: joi.string().min(3).max(60).required(),
	description: joi.string().min(3).max(600).required(),
	userId: joi.string().required()
})