import { NextFunction, Request, Response } from "express";

function requireRole(role:'user' | 'admin') {
    
    return (req: Request, res: Response, next: NextFunction) => {
        const authReq = req as any;
        if (!authReq.user) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        if (authReq.user.role !== role) {
            return res.status(403).json({ message: "Forbidden" });
        }

        next();
    };
}

export default requireRole;