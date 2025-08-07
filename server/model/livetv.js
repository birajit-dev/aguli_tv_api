const mongoose = require('mongoose');

const LiveTvScheme = new mongoose.Schema({
    live_tv_name:{
        type: String,
        required: 'Yes'
    },
    live_tv_link:{
        type: String,
        required: 'Yes'
    }
});
module.exports = mongoose.model('livetv', LiveTvScheme, 'livetv');