const { Firestore } = require('@google-cloud/firestore');
const firestore = new Firestore({
  projectId: process.env.FIRESTORE_PROJECT_ID,
});

module.exports = firestore;
