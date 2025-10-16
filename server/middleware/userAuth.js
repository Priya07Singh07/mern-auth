import jwt from "jsonwebtoken"

const userAuth = async (req,res,next)=>{
    const{token}= req.cookies;

    if(!token){
        return res.json({success: false, message : " not authorised login again"})
    }
    try{
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

        if(tokenDecode.id){
            req.userId =tokenDecode.id;
        }else{
             return res.json({success: false, message : " not authorised login again"})
        
            }
            next();


    }catch(error){
        res.json({sucess:false,message:error.message});
    }

}
export default userAuth;