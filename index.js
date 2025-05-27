const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'SaMMFvMXnTwguYqK';

app.use(bodyParser.json());

const verifySignature = (req, res, buf) => {
  const signature = req.headers['x-passslot-signature'];
  if (!signature) {
    console.error('No signature provided');
    return res.status(401).send('No signature provided');
  }

  const hmac = crypto.createHmac('sha1', SECRET_KEY);
  hmac.update(buf, 'utf-8');
  const digest = `sha1=${hmac.digest('hex')}`;

  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest))) {
    console.error('Invalid signature');
    return res.status(403).send('Invalid signature');
  }
};

app.post('/webhook', async (req, res) => {
  const { type, data } = req.body;
  console.log('Evento recibido:', JSON.stringify(req.body, null, 2));

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
    const userResponse = await axios.get(`https://app.chatgptbuilder.io/api/users/find_by_custom_field?field_id=480449&value=${passSerialNumber}`, {
      headers: {
        'accept': 'application/json',
        'X-ACCESS-TOKEN': '1872077.CwMkMqynAn4DL78vhHIBgcyzrcpYCA08Y8WnAYZ2pccBlo'
      }
    });

    if (userResponse.data.data.length === 0) {
      console.error('Usuario no encontrado con el passSerialNumber proporcionado');
      return res.status(404).send('Usuario no encontrado');
    }

    const userId = userResponse.data.data[0].id;

    const messageResponse = await axios.post(`https://app.chatgptbuilder.io/api/users/${userId}/send/1709878531050`, {}, {
      headers: {
        'accept': 'application/json',
        'X-ACCESS-TOKEN': '1872077.CwMkMqynAn4DL78vhHIBgcyzrcpYCA08Y8WnAYZ2pccBlo'
      }
    });

    console.log('Mensaje enviado exitosamente al usuario:', messageResponse.data);
    res.status(200).send('Evento procesado con éxito y mensaje enviado.');
  } catch (error) {
    console.error('Error al procesar el evento o al enviar el mensaje:', error.response?.data || error.message);
    res.status(500).send('Error al procesar el evento o al enviar el mensaje');
  }
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
