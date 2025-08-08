const mongoose = require('mongoose');

const AdScheme = new mongoose.Schema({
    ads_name: String,
    ads_type: String,
    ads_screen: String,
    ads_link: String,
    ads_status: String,
    ads_image: String,
    ads_sequence: Number,
    created_at: { type: Date, default: Date.now },
});

module.exports = mongoose.model('ads', AdScheme);
