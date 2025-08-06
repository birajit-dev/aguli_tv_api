const mongoose = require('mongoose');

const VideoSchema = new mongoose.Schema({
  video_id: String,
  video_tittle: String,
  video_description: String,
  video_key: String,
  video_url: String,
  video_cat: String,
  video_thumb: String,
  video_status: String,
  video_date: String,
  video_views: String,
  video_likes: String,
  video_comments: String,
  createdat: String,
});

const VideoModel = mongoose.model('videos', VideoSchema);

module.exports = VideoModel;
