import {Request , Response , NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import {PrismaClient , User} from '@prisma/client';

const JWT_SECRET = 'SUPER SECRET';

const prisma = new PrismaClient();

type AuthRequest = Request & {user?:User};

export async function authenticateToken(
    req : AuthRequest,
    res : Response,
    next : NextFunction
){
    // Authenticate
    const authHeader = req.headers['authorization'];
    const jwtToken = authHeader?.split(' ')[1];

    if(!jwtToken){
        return res.sendStatus(401);
    }

    //decode the jwt token
    try {
        const payload = await( jwt.verify(jwtToken, JWT_SECRET)) as {tokenId : number};
        const dbToken = await prisma.token.findUnique({
            where : {
                id : payload.tokenId
            },
            include : {
                user:true
            }
        });

        if(!dbToken?.valid || dbToken?.expiration < new Date()){
            return res.status(401).json({error : 'API token expired'});
        }

        req.user = dbToken.user;
    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            // Handle invalid signature or token errors
            console.error('Invalid token:', error.message);
        } else if (error instanceof jwt.TokenExpiredError) {
            // Handle expired token error
            console.error('Token expired:', error.message);
        } else {
            // Handle other verification errors
            console.error('Token verification failed:', error);
        }
        return res.sendStatus(401);
    }
    next();
}

