import express from 'express';
import config from './config';

const app = express();

app.get('/', (req, res) => {
  res.send('Server is ready');
});

app.listen(config.PORT, () => { 
  console.log(`Server is running on http://localhost:${config.PORT}`);
});