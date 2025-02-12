import { Router } from "express";
import { registerUser } from "../controllers/user.controller.js";

const userRouter = Router()

userRouter.route("/register").post(registerUser);
// router.route("/login").post(login);

export default userRouter