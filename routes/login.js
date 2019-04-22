var express = require('express');
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');

var SEED = require('../config/config').SEED;

var app = express();
var Usuario = require('../models/usuario');

// Google 
const { OAuth2Client } = require('google-auth-library');
const GOOGLE_CLIENT_ID = require('../config/config').GOOGLE_CLIENT_ID;
const GOOGLE_SECRET = require('../config/config').GOOGLE_SECRET;


//===============================================================
//      Autentificación de google
//===============================================================

app.post('/google', (req, res) => {

    var token = req.body.token || '';

    const client = new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_SECRET);

    const ticket = client.verifyIdToken({
        idToken: token,
        audience: GOOGLE_CLIENT_ID
    });

    ticket.then(data => {

        Usuario.findOne({ email: data.payload.email }, (err, usuarioDB) => {

            if (err) {
                return res.status(500).json({
                    ok: false,
                    mensaje: 'Error al buscar usuario',
                    errors: err
                });
            }

            if (usuarioDB) {

                if (usuarioDB.google === false) {
                    return res.status(400).json({
                        ok: false,
                        mensaje: 'Debe usar autentificación normal'
                    });
                } else {
                    var token = jwt.sign({ usuario: usuarioDB }, SEED, { expiresIn: 14400 }); // 4 horas

                    res.status(200).json({
                        ok: true,
                        usuario: usuarioDB,
                        token: token,
                        id: usuarioDB._id
                    });
                }
            } else {
                // usuario no existe y hay que crearlo
                var usuario = new Usuario();

                usuario.nombre = data.payload.name;
                usuario.email = data.payload.email;
                usuario.img = data.payload.picture;
                usuario.google = true;
                usuario.password = ':)';

                usuario.save((err, usuarioDB) => {

                    var token = jwt.sign({ usuario: usuarioDB }, SEED, { expiresIn: 14400 }); // 4 horas

                    res.status(200).json({
                        ok: true,
                        usuario: usuarioDB,
                        token: token,
                        id: usuarioDB._id
                    });
                });
            }
        });

    }).catch(err => {
        if (err) {
            return res.status(400).json({
                ok: false,
                mensaje: 'Token no válido',
                errors: err
            });
        }
    });
});


//===============================================================
//      Autentificación normal
//===============================================================


app.post('/', (req, res) => {

    var body = req.body;

    Usuario.findOne({ email: body.email }, (err, usuarioDB) => {

        if (err) {
            return res.status(500).json({
                ok: false,
                mensaje: 'Error al buscar usuario',
                errors: err
            });
        }

        if (!usuarioDB) {
            return res.status(400).json({
                ok: false,
                mensaje: 'Credenciales incorrectas - email',
                errors: err
            });
        }

        if (!bcrypt.compareSync(body.password, usuarioDB.password)) {
            return res.status(400).json({
                ok: false,
                mensaje: 'Credenciales incorrectas - password',
                errors: err
            });
        }

        // Crear un token!!!
        usuarioDB.password = ':)';

        var token = jwt.sign({ usuario: usuarioDB }, SEED, { expiresIn: 14400 }); // 4 horas

        res.status(200).json({
            ok: true,
            usuario: usuarioDB,
            token: token,
            id: usuarioDB._id
        });
    });
});

module.exports = app;