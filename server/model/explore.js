const mongoose = require('mongoose');

const ExploreSchema = new mongoose.Schema({
  explore_id: String,
  explore_title: String,
  explore_descriptions: String,
  explore_thumb: [String],
  explore_slug: String,
  explore_status: String,
  explore_likes: String,
  createdat: String,
});

const ExploreModel = mongoose.model('explores', ExploreSchema);

module.exports = ExploreModel;