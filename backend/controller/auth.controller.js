const Usuario = require('../models/Usuario')

const cryptoJs = require('crypto-js')
const CHAVE_SECRETA = 'segredo'

const login = async (req, res)=>{
    const valores = req.body
    
    if(!valores.email || !valores.senha){
        return res.status(400).json({message: 'Preencha todos os campos!'})
    }
    
    try {
        const dados = await Usuario.findOne({where: {email: valores.email}})
        
        if(!Usuario){
            return res.status(400).json({message: 'Usuário não encontrado!'})
        }
        
        const bits = cryptoJs.AES.decrypt(dados.senha, CHAVE_SECRETA)
        const senha = bits.toString(cryptoJs.enc.Utf8)
        
        if(valores.senha !== senha){
            return res.status(403).json({message: 'Acesso negado!'})
        }

        const tempo =  60 * 60 * 1000 * 1.5
        const horarioExpirar = Date.now + tempo

        const payload = {
            idUsuario: valores.codUsuario,
            nome: valores.nome,
            expiraEm: horarioExpirar 
        }

        const token = cryptoJs.AES.encrypt(JSON.stringify(payload),CHAVE_SECRETA).toString

        return res.status(200).json({
            message: 'Usuário não encontrado!',
            nome: dados.nome,
            token: token
        })
    } catch (err) {
        return res.status(500).json({message: 'houve um problema ao fazer o login'})
    }
}

module.exports = { login }