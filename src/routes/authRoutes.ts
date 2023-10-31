import {Router} from 'express';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';
import { create } from 'domain';
// import {sendEmailToken} from '../services/emailService';

const EMAIL_TOKEN_EXPIRATION_MINUTES = 10;
const AUTHENTICATION_EXPIRATION_HOURS = 2;
const JWT_SECRET = 'SUPER SECRET';

const router = Router();
const prisma = new PrismaClient();

// Generate a random 6 digit number as the email token
function generateEmailToken(): string {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateAuthToken(tokenId: number): string {
    const jwtPayload = { tokenId };
  
    return jwt.sign(jwtPayload, JWT_SECRET, {
      algorithm: 'HS256',
      noTimestamp: true,
    });
}



// Create  User if not 
//Generate emailToken and send it to email
router.post('/login', async (req , res)=>{
    const {email} = req.body;

    //generate Token
    const emailToken = generateEmailToken();
    const expiration = new Date(
        new Date().getTime() + EMAIL_TOKEN_EXPIRATION_MINUTES*60*1000
    );

    try{
        const createdToken = await prisma.token.create({
            data:{
                type:'EMAIL',
                emailToken,
                expiration,
                valid : true,
                user:{
                    connectOrCreate :{
                        where : {email},
                        create:{email},
                    }
                }
            }
        });
        // console.log(createdToken);
        //TODO send emailToken to user's email

        // await sendEmailToken(email,emailToken);
        res.sendStatus(200);
    }catch(e){
        console.log(e);
        res.status(400).json({error: "Couldn't Start the authentication process"});


    }
});

// Validate the email token
// Generate a long-lived JWT token

router.post('/authenticate', async (req,res) => {
    const {email,emailToken} = req.body;
    // console.log(email,emailToken);
    const dbEmailToken = await prisma.token.findUnique({
        where: {
          emailToken,
        },
        include: {
          user: true,
        },
      });
    // console.log(dbEmailToken)
    // Validations
    if (!dbEmailToken || !dbEmailToken.valid) {
        return  res.status(401).send("Unauthorized: Suimasen Des!!");;
    }
    if (dbEmailToken.expiration < new Date()) {
        return res.status(401).json({ error: 'Token expired!' });
    }
    
    if (dbEmailToken?.user?.email !== email) {
        return res.sendStatus(401);
    }
    
    // Generate API token
    const expiration = new Date(
        new Date().getTime() + AUTHENTICATION_EXPIRATION_HOURS *60*60*1000
    );

    const apiToken = await prisma.token.create({
        data:{
            type : 'API',
            expiration,
            user : {
                connect : {
                    email
                }
            }

        }
    })

    //Invalidate EMAIL token
    await prisma.token.update({
        where: { id: dbEmailToken.id },
        data: { valid: false },
    });

    // generate the JWT token
    const authToken = generateAuthToken(apiToken.id);

  res.json({ authToken });
});


export default router;