import asyncHandler from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { upploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";

const generateAccessAndRefreshToken = async (userId) =>{
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({validateBeforeSave : false});

        return {refreshToken, accessToken};

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating the access and refresh token")
    }
}

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

    const existedUser = await User.findOne({
        $or: [{username}, {email}]  //here this is a check the user being registered should not laready exist and we can get this by user databse model that either email or username should be unique
    })
    console.log(existedUser);

    if(existedUser){
        throw new ApiError(409, "user with same email or username already exists");
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0){
        coverImageLocalPath = req.files.coverImage[0].path;
    }

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
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select("-password -refreshToken");

    if(!createdUser){
        throw new ApiError(500, "Somethign went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "Registeration succesfull")
    )
})

const loginUser = asyncHandler(async (req,res) =>{
    //getting the data from the user 
    // validating the data in the data for the same password and email
    
    const {username, email, password} = req.body;

    if(!(username || email)){
        throw new ApiError(400, "username or email is required");
    }

    const user = await User.findOne({
        $or: [{username}, {email}]
    })

    if(!user){
        throw new ApiError(404, "User does not exists");
    }

    const isPasswordValid = await user.isPasswordCorrect(password);

    if(!isPasswordValid){
        throw new ApiError(401, "Password is not valid");
    }

    const {refreshToken, accessToken} = await generateAccessAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    const options = {
        httpOnly: true,
        secure: true
    }

    return res.
    status(200).
    cookie("accessToken", accessToken, options).
    cookie("refreshtoken", refreshToken, options).
    json(
        new ApiResponse(
            200,
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged in successfully"
        )
    )
})

const logoutUser = asyncHandler(async (req, res) =>{
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                refreshToken: 1 //this removes the field from the document
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookies("accessToken", options)
    .clearCookies("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out seccussfelly"));
})

const refreshAccessToken = asyncHandler(async (req, res) =>{
    const incomingRefreshToken = req.cookie.refreshToken || req.body.refreshToken;

    if(!incomingRefreshToken){
        throw new ApiError(401, "unauthorised request");
    }

    const decodedToken = jwt.verify(
        incomingRefreshToken,
        process.env.REFRESH_TOKEN_SECRET
    )

    const user = await User.findById(decodedToken?._id);

    if(!user){
        throw new ApiError(401, "Invalid refresh token");
    }

    if(incomingRefreshToken !== user?.refreshToken){
        throw new ApiError(401, "Refresh token expired or used");
    }

    const options = {
        httpOnly: true,
        secure: true
    }

    const {accessToken, newRefreshToken} = await generateAccessAndRefreshToken(user._id);

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", newRefreshToken, options)
    .json(
        new ApiError(
            200,
            {accessToken, refreshToken: newRefreshToken},
            "accessToken refreshed successfully"
        )
    )
})

const changeCurrentPassword = asyncHandler(async (req, res) =>{
    const {oldPassword, newPassword} = req.body;

    const user = await User.findById(req.user?._id);
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect){
        throw new ApiError(400, "Invalid Password");
    }

    user.password = newPassword;
    await user.save({validateBeforeSave: false})

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"));
})

const getCurrentUser = asyncHandler(async (req, res) =>{
    return res
    .status(200)
    .json(new ApiResponse(200, req.user, "Current User Fetched successfully"));
})

const updateAccount = asyncHandler(async (req, res) =>{
    const {fullName, email} = req.body;

    if(!fullName || !email){
        throw new ApiError(400, "All fields are required");
    }
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                email
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200, user, "Account details updated successfully"))
})

const updateUserAvatar = asyncHandler(async (req, res) =>{
    const avatarLocalPath = req.file?.path;

    if(!avatarLocalPath){
        throw new ApiError(400, "File is missing");
    }

    const avatar = await upploadOnCloudinary(avatarLocalPath)

    if (!avatar.url) {
        throw new ApiError(400, "Error on uploading the file to cloudinary");
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                avatar: avatar.url
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200, user, "avatar updated"))
})

const updateUserCoverImage = asyncHandler(async (req, res) =>{
    const coverImageLocalPath = req.file?.path;

    if(!coverImageLocalPath){
        throw new ApiError(400, "File is missing");
    }

    const coverImage = await upploadOnCloudinary(coverImageLocalPath)

    if (!coverImage.url) {
        throw new ApiError(400, "Error on uploading the file to cloudinary");
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                coverImage: coverImage.url
            }
        },
        {new: true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200, user, "cover image updated"))
})

const getUserChannelProfile = asyncHandler(async (req, res) =>{
    const {username} = req.params

    if(!username){
        throw new ApiError(400, "username is missing");
    }
    
    const channel = User.aggregate([
        {
            $match: {
                username : username?.toLowerCase()
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            }
        },
        {
            $addFields: {
                subscribersCount: {
                    $size: "$subscribers"
                },
                channelsSubscribedToCount: {
                    $size: "$subscribedTo"
                },
                isSubscribed: {
                    $cond: {
                        if: {$in: [req.user?._id, "$subscribers.subcriber"]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: {
                fullName: 1,
                username: 1,
                subscribersCount: 1,
                channelsSubscribedToCount: 1,
                isSubscribed: 1,
                avatar: 1,
                coverImage: 1,
                email: 1
            }
        }
    ])

    if(!channel?.length){
        throw new ApiError(400, "Channel does not exists");
    }

    return res
    .status(200)
    .json(
        new ApiResponse(200, channel[0], "user channel fetched successfully")
    )
})

const getWatchHistory = asyncHandler(async (req, res) =>{
    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project: {
                                        fullName: 1,
                                        username: 1,
                                        avatar: 1
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields: {
                            owner: {
                                $first: "$owner"
                            }
                        }
                    }
                ]
            }
        }
    ])

    return res
    .status(200)
    .json(
        new ApiResponse(200, user[0].watchHistory, "watch history fetched successfully")
    )
})

export {registerUser
    ,loginUser
    ,logoutUser
    ,refreshAccessToken
    ,changeCurrentPassword
    ,getCurrentUser
    ,updateAccount
    ,updateUserAvatar
    ,updateUserCoverImage
    ,getUserChannelProfile
    ,getWatchHistory
};