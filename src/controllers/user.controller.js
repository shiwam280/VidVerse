import asyncHandler from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { upploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";

const registerUser = asyncHandler(async (req, res) =>{
    //get user data from client as the followed in the user model in database
    //validation - check if any of the fields are not left empty from the user
    //check if the user already exits either through email or username
    // check for images provided by the user and if any of them are required
    // if they are available upload them to cloudinary
    //create an object as information on mongoDB is daved in object format
    // check for user created or not
    //remove password and refresh token field from the response
    // return response and if not created return an error

    const {fullName, email, username, password}  = req.body;
    console.log(fullName, email, username, password);

    if([fullName, email, username, password].some((field) =>  field?.trim() === "")){
        throw new ApiError(400, "field is empty")
    }

    const existedUser = User.findOne({
        $or: [{username}, {email}]  //here this is a check the user being registered should not laready exist and we can get this by user databse model that either email or username should be unique

    })
    console.log(existedUser);

    if(existedUser){
        throw new ApiError(409, "user with same email or username already exists");
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files?.coverImage[0]?.path;

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar is required");
    }

    const avatar = await upploadOnCloudinary(avatarLocalPath)
    const coverImage = await upploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400, "Avatar is required");
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowercase()
    })

    const createdUser = await User.findById(user._id).select("-password -refreshToken");

    if(!createdUser){
        throw new ApiError(500, "Somethign went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "Registeration succesfull")
    )
})

export {registerUser};