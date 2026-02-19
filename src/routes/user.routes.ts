import { Router } from "express";
import requireAuth from "../middleware/requireAuth";
import {
  getUserProfile,
  getUsersList,
} from "../controllers/auth/user.controller";
import requireRole from "../middleware/requireRole";

const userRouter = Router();

userRouter.get("/profile", requireAuth, getUserProfile);
userRouter.get("/users-list", requireAuth, requireRole("admin"), getUsersList);

export default userRouter;
