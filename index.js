console.log('index.js is running...');
const hello = (name) => {
  console.log('hello function is running...');
  return `Hello, ${name}!`;
}

module.exports = {
  hello,
};
