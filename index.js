require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const axios = require('axios');

const app = express();

// --- CONFIGURACIÓN DEL PROYECTO (Leído desde .env) ---
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SMARTPASSES_SECRET_KEY;
const API_TOKEN = process.env.CHATGPT_BUILDER_TOKEN;
const CUSTOM_FIELD_ID = process.env.CUSTOM_FIELD_ID;
const MESSAGE_ID = process.env.MESSAGE_ID;
// ----------------------------------------------------

// --- FUNCIÓN DE VERIFICACIÓN DE FIRMA ---
const verifySignature = (req, res, buf) => {
  const signature = req.headers['x-passslot-signature'];
  if (!signature) {
    // Lanza un error si no hay firma.
    throw new Error('No signature provided');
  }

  const hmac = crypto.createHmac('sha1', SECRET_KEY);
  hmac.update(buf, 'utf-8'); // 'buf' es el cuerpo crudo de la petición
  const digest = `sha1=${hmac.digest('hex')}`;

  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest))) {
    // Lanza un error si la firma no es válida.
    throw new Error('Invalid signature');
  }
};

// --- MIDDLEWARE ---
// Usamos bodyParser.json, pero le pasamos nuestra función de verificación.
// Si verifySignature lanza un error, la petición se detiene aquí.
app.use(bodyParser.json({ verify: verifySignature }));

// --- RUTA DEL WEBHOOK ---
app.post('/webhook', async (req, res) => {
  // Si el código llega hasta aquí, la firma ya fue verificada con éxito.
  const { type, data } = req.body;
  console.log('Evento recibido y verificado:', JSON.stringify(req.body, null, 2));

  if (type === 'webhook.verify') {
    console.log('Manejando verificación del webhook con token:', data.token);
    return res.status(200).json({ token: data.token });
  }

  const passSerialNumber = data?.passSerialNumber;
  if (!passSerialNumber) {
    console.error('passSerialNumber no encontrado en el evento');
    return res.status(400).send('passSerialNumber no encontrado');
  }

  try {
    const userResponse = await axios.get(`https://app.chatgptbuilder.io/api/users/find_by_custom_field?field_id=${CUSTOM_FIELD_ID}&value=${passSerialNumber}`, {
      headers: { 'accept': 'application/json', 'X-ACCESS-TOKEN': API_TOKEN }
    });

    if (userResponse.data.data.length === 0) {
      console.error('Usuario no encontrado con el passSerialNumber proporcionado');
      return res.status(404).send('Usuario no encontrado');
    }

    const userId = userResponse.data.data[0].id;

    const messageResponse = await axios.post(`https://app.chatgptbuilder.io/api/users/${userId}/send/${MESSAGE_ID}`, {}, {
      headers: { 'accept': 'application/json', 'X-ACCESS-TOKEN': API_TOKEN }
    });

    console.log('Mensaje enviado exitosamente al usuario:', messageResponse.data);
    res.status(200).send('Evento procesado con éxito y mensaje enviado.');
  } catch (error) {
    console.error('Error al procesar el evento o al enviar el mensaje:', error.response?.data || error.message);
    res.status(500).send('Error al procesar el evento o al enviar el mensaje');
  }
});

// --- MANEJO DE ERRORES DE FIRMA ---
// Este middleware especial atrapa los errores lanzados por verifySignature.
app.use((err, req, res, next) => {
    if (err.message === 'No signature provided') {
        console.error('Rechazado: Sin firma.');
        return res.status(401).send(err.message);
    }
    if (err.message === 'Invalid signature') {
        console.error('Rechazado: Firma inválida.');
        return res.status(403).send(err.message);
    }
    // Para otros errores inesperados
    console.error(err);
    res.status(500).send('Error interno del servidor.');
});


app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
