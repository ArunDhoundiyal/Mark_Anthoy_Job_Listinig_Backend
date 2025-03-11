const Joi = require('joi')

const checkUserCredentials = Joi.object({
    user_name:Joi
    .string()
    .max(256)
    .pattern(/^[a-zA-Z]+(?: [a-zA-Z]+)*$/)
    .required()
    .messages({
        "string.pattern.base":
        "User name must only contain letters, with optional single spaces between words..!",
      "string.max": "User name must be below or equal to 150 character long..!",
      "any.required": "User name is required..!"
    }),
    user_email:Joi.string().email().required().messages({
        "string.email":"Invalid email address format..!",
        "any.required":"User email is required..!"
    }),
    user_password:Joi.string()
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&*!]).{8,}$/)
    .required()
    .messages({
      "string.pattern.base":
        "Password must include at least one uppercase letter, one lowercase letter, one digit, one special character (@#$%^&*!), and be at least 8 characters long..!",
      "any.required": "Password is required..!",
    }),
    contact_phonenumber: Joi.string()
    .pattern(/^[6789]\d{9}$/) 
    .required()
    .messages({
      "string.pattern.base": "Invalid phone number format..!",
      "any.required": "User phone number is required..!",
    })
})

const checkLoginCredentials = Joi.object({
  user_email:Joi.string().email().required().messages({
    "string.email":"Invalid email address format..!",
    "any.required":"User email is required..!"
  }),
  user_password:Joi.string().pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&*!]).{8,}$/).required().messages({
  "string.pattern.base":
    "Password must include at least one uppercase letter, one lowercase letter, one digit, one special character (@#$%^&*!), and be at least 8 characters long..!",
  "any.required": "Password is required..!",
})
})



module.exports = {checkUserCredentials, checkLoginCredentials} 