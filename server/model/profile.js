const mongoose = require('mongoose');

const ProfileSchema = new mongoose.Schema({
  googleId: String,
  full_name: String,
  email: String,
  profile_picture: String,
  phone: String,
  user_code: String,
  status: String,
  createdat: { 
    type: String,
    default: new Date().toISOString()
  }
});
const ProfileModel = mongoose.model('profiles', ProfileSchema);
module.exports = ProfileModel;
