const { response } = require("express");
const bcrypt = require("bcryptjs");
const Usuario = require('../models/usuario');
const { generarJWT } = require("../helpers/jwt");
const usuario = require("../models/usuario");

const crearUsuario = async (req, res = response) => {

    const { email, password } = req.body;

    try {

        const existEmail = await Usuario.findOne({ email});
        if (existEmail) {
            return res.status(400).json({
                ok: false,
                msg: 'El correo ya existe'
            });
        }

        const usuario = new Usuario(req.body);
        /// encriptar contraseña
        const salt = bcrypt.genSaltSync();
        usuario.password = bcrypt.hashSync(password, salt);

        await usuario.save();


        const token = await generarJWT(usuario.id);
        //Generar el JWT

        res.json({
            ok: true,
            usuario,
            token
        });

    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Hable con el admin'
        });
    }

    
}


const login = async (req, res = response) => {

    const { email, password } = req.body;

    try {

        const usuarioDB = await Usuario.findOne({email});
        if(!usuarioDB) {
            return res.status(404).json({
                ok: false,
                msg: 'Email no encontrado'
            });
        }

        const validPassword = bcrypt.compareSync(password, usuarioDB.password);
        if(!validPassword) {
            return res.status(400).json({
                ok: false,
                msg: 'La contrasela es inválida'
            });
        }

        const token = await generarJWT(usuarioDB.id);

        return res.json({
            ok: true,
            usuario: usuarioDB,
            token
        })

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            ok: false,
            msg: 'Hable con el admin'
        })
    }


    
}


const renewToken = async (req, res = response) => {


    const uid = req.uid;

    const token = await generarJWT(uid);

    const usuario = await Usuario.findById(uid);

    res.json({
        ok: true,
        usuario,
        token
    })
} 

module.exports = {
    crearUsuario,
    login,
    renewToken
}