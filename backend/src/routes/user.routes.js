import { Router } from "express";
import { registerUser, loginUser, logoutUser, refreshAccessToken } from "../controllers/user.controller.js";
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
userRouter.route("/logout").post(verifyJWT, logoutUser);
userRouter.route("/login").post(loginUser);

//Secure routes
userRouter.route("/refresh-token").post(verifyJWT, refreshAccessToken);

export default userRouter