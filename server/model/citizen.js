const mongoose = require('mongoose');
var AutoIncrement = require('mongoose-sequence')(mongoose);
const citizenSchema = new mongoose.Schema({
    citizen_id: Number,
    post_name: String,
    post_url: String,
    post_content: String,
    post_image: String,
    profile_name: String,
    post_status: String,
    phone_number: String,
    created_at: String,
});

citizenSchema.plugin(AutoIncrement, {id:'citizen_id',inc_field: 'citizen_id'});
module.exports = mongoose.model('citizen', citizenSchema, 'citizen');