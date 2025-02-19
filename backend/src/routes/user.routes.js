import { Router } from "express";
import { registerUser, loginUser, logoutUser, refreshAccessToken, changePassword, getCurrentUser, updateAccountDetails, updateUserAvatar, updateUserCoverImage, getUserChannelProfile, getWatchHistory } from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const userRouter = Router()

userRouter.route("/register").post(
    upload.fields([
        { name: 'avatar', maxCount: 1 },
        { name: 'coverImage', maxCount: 1 }
    ]),
    registerUser
);

userRouter.route("/login").post(loginUser);

//Secure routes
userRouter.route("/logout").post(verifyJWT, logoutUser);
userRouter.route("/refresh-token").post(verifyJWT, refreshAccessToken);
userRouter.route("/change-password").post(verifyJWT, changePassword);
userRouter.route("/current-user").get(verifyJWT, getCurrentUser);
userRouter.route("/change-password").patch(verifyJWT, updateAccountDetails);
userRouter.route("/avatar").patch(verifyJWT, upload.single("avatar"), updateUserAvatar);
userRouter.route("/cover-image").patch(verifyJWT, upload.single("coverImage"), updateUserCoverImage);
userRouter.route("/search-profile/:username").get(verifyJWT, getUserChannelProfile);
userRouter.route("/history").get(verifyJWT, getWatchHistory);


export default userRouter