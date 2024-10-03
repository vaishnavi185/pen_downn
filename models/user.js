import mongoose, { Schema } from "mongoose";

const userschema=new mongoose.Schema({
    name:{type:String,require:true,trim:true},
    email:{type:String,require:true,trim:true},
    password:{type:String,require:true,trim:true},
    tc:{type:Boolean,require:true},
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date }
})
const usermodel = mongoose.model("user",userschema)
export default usermodel;