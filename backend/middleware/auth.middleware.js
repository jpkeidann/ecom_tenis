const cryptoJs = require('crypto-js')
const CHAVE_SECRETA = 'segredo'

function authMiddleware(req,res,next){
    const token = req.headers['authorization']

    if(!token){ 
        return res.status(403).json({message: 'Acesso negado! , faça login.'})
    }
    
    try {
        const bytes = cryptoJs.AES.decrypt(token, CHAVE_SECRETA)
        const dadosDescriptografados = bytes.toString(cryptoJs.enc.Utf8)
        
        if(!dadosDescriptografados){
            return res.status(403).json({message: 'Acesso negado!'})
        }
        
        const payload = JSON.parse(dadosDescriptografados)
        
        if(Date.now() > payload.expiraEm){
            return res.status(403).json({message: 'Sessão expirada! , faça login!'})
        }

        req.usuario = payload

        next()
    } catch (err) {
        console.error('Falha na autenticação',err)
        return res.status(401).json({message: 'Falha na autenticação'})
    }
}

authMiddleware()