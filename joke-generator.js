const https = require('https');

function getRandomJoke() {
  return new Promise((resolve, reject) => {
    https.get('https://official-joke-api.appspot.com/random_joke', (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        try {
          const joke = JSON.parse(data);
          console.log(`\n${joke.setup}`);
          console.log(`${joke.punchline}\n`);
          resolve(joke);
        } catch (error) {
          reject(error);
        }
      });
    }).on('error', (error) => {
      reject(error);
    });
  });
}

// Get a random joke
getRandomJoke().catch(console.error);
