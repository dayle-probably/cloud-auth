console.log('index.js is running...');
const hello = (name) => {
  console.log('hello function is running...');
  return `Hello, ${name}!`;
}

const passport = require('./passport');

module.exports = {
  hello,
  passport,
};
