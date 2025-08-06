const mongoose = require('mongoose');
var AutoIncrement = require('mongoose-sequence')(mongoose);
const categorySchema = new mongoose.Schema({
    cat_id: Number,
    cat_name: String,
    cat_code: String,
    cat_thumb: String,
    cat_slug: String,
    cat_status: String,
    cat_order: Number,
    update_date: String,
});

categorySchema.plugin(AutoIncrement, {id:'cat_seq',inc_field: 'cat_seq'});
module.exports = mongoose.model('category', categorySchema, 'category');