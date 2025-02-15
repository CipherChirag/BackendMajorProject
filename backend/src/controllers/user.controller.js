import asyncHandler from '../utils/asyncHandler.js';
import ApiError from '../utils/ApiError.js';
import { User } from '../models/user.model.js';
import uploadOnCloudinary from '../utils/cloudinary.js';
import ApiResponse from '../utils/ApiResponse.js';
import jwt from 'jsonwebtoken';

const generateAccessandRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = await user.generateAccessToken();
        const refreshToken = await user.generateRefreshToken();
        user.refreshToken = refreshToken;

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });
        return { accessToken, refreshToken };
    } catch(error) {
        throw new ApiError(500, "Error while generating refresh and access token")
    }
}

const registerUser = asyncHandler( async (req, res) => {
    const {fullname, email, password, username} = req.body;
    if( [fullname, email, username, password].some((field) => field?.trim() === "")) {
        throw new ApiError(400, "All fields are required");
    }

    const existingUser = await User.findOne({
        $or: [{ email }, { username }]
    });
    if (existingUser) {
        throw new ApiError(409, "User with email or username already exists");
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    if(!avatarLocalPath) {
        throw new ApiError(400, "Avatar is required");
    }
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    if(!avatar) {
        throw new ApiError(500, "Error uploading avatar");
    }

    const coverImageLocalPath = req.files?.coverImage?.[0]?.path;
    let coverImage;
    if (coverImageLocalPath) {
        coverImage = await uploadOnCloudinary(coverImageLocalPath);
    }

    const user = await User.create({
        fullname,
        email,
        username: username.toLowerCase(),
        password,
        avatar: avatar.secure_url,
        coverImage: coverImage?.secure_url
    })

    const createdUser = await User.findById(user._id).select("-password -refreshToken");
    if(!createdUser) {
        throw new ApiError(500, "Something went wrong while creating the user!");
    }

    return res.status(201).json(new ApiResponse(200, createdUser, "User created successfully"));

});

const loginUser = asyncHandler( async (req, res) => {
    const {emailorusername, password} = req.body
    if(!emailorusername) {
        throw new ApiError(400, "Username or email is required")
    }
    const user = await User.findOne({
        $or: [{ email }, { username }]
    });
    if (!user) {
        throw new ApiError(409, "User with email or username doesn't exists");
    }
    if(!password) {
        throw new ApiError(400, "Password is required")
    }
    const checkPassword = await user.isPasswordCorrect(password);
    if(!checkPassword) {
        throw new ApiError(401, "Invalid User Credentials")
    }

    const { accessToken, refreshToken } = await generateAccessandRefreshToken(user._id);

    const loggedInUser = User.findById(user._id).select("-password -refreshToken");
    
    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(200, loggedInUser, "User logged in successfully")
    );

});

const logoutUser = asyncHandler( async (req, res) => {
    await User.findByIdAndUpdate(req.user._id, { 
        $set: {
            refreshToken: undefined
        }
    }, {
        new: true
    });

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out successfully"));
});

const refreshAccessToken = asyncHandler( async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;
    if(!incomingRefreshToken) {
        throw new ApiError(401, "Unauthenticated");
    }
    try {
        const decodedToken = jwt.verify (incomingRefreshToken, process.env.JWT_REFRESH_SECRET);
    
        const user = await User.findById(decodedToken?._id);
        if(!user || user.refreshToken !== incomingRefreshToken) {
            throw new ApiError(401, "Invalid refresh token");
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken, newRefreshToken} = await generateAccessandRefreshToken(user._id);
    
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200, 
                { accessToken, refreshToken: newRefreshToken },
                "Access token refreshed successfully"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid Refresh Token");
    }

});

const changePassword = asyncHandler( async (req, res) => {
    const {oldPassword, newPassword, confPassword} = req.body;
    if(!(confPassword === newPassword)) {
        throw new ApiError(400, "New password and confirm passwords do not match");
    }
    if(!oldPassword || !newPassword) {
        throw new ApiError(400, "Old password and new password are required");
    }
    const user = User.findById(req.user._id)
    if(!user) {
        throw new ApiError(500, "Error while changing password");
    }
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);
    if(!isPasswordCorrect) {
        throw new ApiError(401, "Invalid old password");
    }
    user.password = newPassword;
    await user.save({ validateBeforeSave: false });

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"));
});

const getCurrentUser = asyncHandler( async (req, res) => {
    return res
    .status(200)
    .json(new ApiResponse(200, req.user, "User found"));
});

const updateAccount = asyncHandler( async (req, res) => {
    const {fullname, email} = req.body;

    if(!fullname || !email) {
        throw new ApiError(400, "At least one field is required");
    }

    const user = User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullname: fullname,
                email: email
            }
        },
        {
            new: true
        }
    ).select("-password -refreshToken");
    return res
    .status(200)
    .json(new ApiResponse(200, user, "User updated successfully"));
});

const updateUserAvatar = asyncHandler( async (req, res) => {
    const avatarLocalPath = req.file?.path;
    if(!avatarLocalPath) {
        throw new ApiError(400, "Avatar is required");
    }
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    if(!avatar.secure_url) {
        throw new ApiError(500, "Error uploading avatar");
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                avatar: avatar.secure_url
            }
        },
        {
            new: true
        }
    ).select("-password -refreshToken");
    
    return res
    .status(200)
    .json(new ApiResponse(200, user, "Avatar updated successfully"));
});

const updateUserCoverImage = asyncHandler( async (req, res) => {
    const coverImageLocalPath = req.file?.path;
    if(!coverImageLocalPath) {
        throw new ApiError(400, "Cover Image is required");
    }
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);
    if(!coverImage.secure_url) {
        throw new ApiError(500, "Error uploading Cover Image");
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                coverImage: coverImage.secure_url
            }
        },
        {
            new: true
        }
    ).select("-password -refreshToken");

    return res
    .status(200)
    .json(new ApiResponse(200, user, "Cover Image updated successfully"));
});

export {
    registerUser, 
    loginUser,
    logoutUser,
    refreshAccessToken,
    changePassword,
    getCurrentUser,
    updateAccount,
    updateUserAvatar,
    updateUserCoverImage
};