//make methods for the user , to register , login and logout
import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import { User } from "../models/userSchema.js";
import ErrorHandler from "../middlewares/error.js";
import { sendToken } from "../utils/jwtToken.js";

export const register = catchAsyncError(async (req, res, next) => {
  const { name, email, phone, role, password } = req.body;
  if (!name || !email || !phone || !role || !password) {
    return next(new ErrorHandler("Please fill all the fields", 400));
  }
  const isEmail = await User.findOne({ email });
  if (isEmail) {
    return next(new ErrorHandler("Email already exists "));
  }

  const user = await User.create({
    name,
    email,
    phone,
    role,
    password,
  });
  sendToken(user, 200, res, "user registered successfully");
});


export const login = catchAsyncError(async(req,res,next)=>{
  const{email,password,role} = req.body;
  if(!email || !password || !role){
    return next(new ErrorHandler("Please enter email and password",400));
  }
   const user = await User.findOne({email}).select("+password");
   if(!user){
     return next(new ErrorHandler("Invalid email or password",400));
   }
   const isPasswordMatched = await user.comparePassword(password);
   if(!isPasswordMatched){
     return next(new ErrorHandler("Invalid email or password",400));
   }
   if(user.role !== role){
     return next(new ErrorHandler("Invalid role",400));
   }
    sendToken(user,200,res,"user logged in successfully");
  });

//logout functionality 

export const logout = catchAsyncError(async(req,res,next)=>{
  res.status(201).cookie("token","",{
    httpOnly:true,
    expires: new Date(Date.now()),
    secure: true,
    sameSite: "None",

  }).json({
    success: true,
    message: "User Logged out successfully",
  });
})

export const getUser = catchAsyncError((req,res,next) =>{
  const user = req.user;
  res.status(200).json({
    success:true,
    user,
  });
});