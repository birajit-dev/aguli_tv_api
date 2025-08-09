const { request } = require('express');
const fs = require('fs'); // File system module to delete files
const path = require('path'); // Path module to handle file paths
const crypto = require('crypto');
var express = require('express');
require('../model/database');
const adminData =  require('../model/login');
const breakingNews = require('../model/breakingnews');
const UserModel = require('../model/insideUser');
const AuthorModel = require('../model/insideUser');
const MediaModel = require('../model/mediaLibrary');
const NewsModel = require('../model/ainews');
const DocumentModel = require('../model/document');
const ImageModel = require('../model/images');
const CategoryModel = require('../model/category');
const ProfileModel = require('../model/profile');
const VideoModel = require('../model/video');
const ExploreModel = require('../model/explore');
const CitizenModel = require('../model/citizen');
const AdsModel = require('../model/ads');
require('dotenv').config(); // To manage API keys securely
const { OpenAI } = require('openai');
const axios = require('axios');
const SaasUserModel = require('../model/saasuser');

const Queue = require('bull');
const moment = require('moment');

const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET; // Put this in .env
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { resolve } = require('path');
//const { rejects } = require('assert');
const { all } = require('express/lib/application');
const { assert } = require('console');
const fetch = require('node-fetch');
const _ = require('lodash');
const { title } = require('process');
const breakingnews = require('../model/breakingnews');
const aws = require('aws-sdk');
const multerS3 = require('multer-s3');
const uploadNewsImage = require('../middleware/uploadNewsImage');

const LiveTVModel = require('../model/livetv');

const admin = require('firebase-admin');

// Initialize Firebase Admin with your service account credentials



const newDate = moment().format('lll');

function getRandomInt(max) {
    return Math.floor(Math.random() * Math.floor(max));
};

      
//API FOR GET ALL ADS
exports.getNewsByCategory = async (req, res) => {
    try {
        const category = req.query.category;
        const page = parseInt(req.query.page) || 1;
        const limit = 10; // Number of items per page
        const skip = (page - 1) * limit;
        const domain = "http://api.aguli.com" // Get domain from query params

        // Validate category parameter
        if (!category) {
            return res.status(400).json({
                success: false,
                message: 'Category parameter is required'
            });
        }

        // Find total count for pagination
        const totalCount = await NewsModel.countDocuments({ 
            post_category: category,
            post_status: 'published' 
        });

        // Get paginated news for the category
        let news = await NewsModel.find({ 
            post_category: category,
            post_status: 'Published'
        })
        .sort({ update_date: -1 })
        .skip(skip)
        .limit(limit)
        .select('post_name post_url post_description post_image update_date author_name')
        .lean(); // Use lean() for better performance

        // Add domain to post_image paths and format dates
        news = news.map(item => ({
            ...item,
            post_image: domain ? `${domain}${item.post_image}` : item.post_image,
            update_date: new Date(item.update_date).toISOString().replace(/\.\d{3}Z$/, 'Z') // Format as 2025-07-29T07:34:00Z
        }));

        // Get ads for home screen
        let ads = await AdsModel.find({
            ads_screen: 'home',
            ads_status: 'active'
        })
        .select('ads_type ads_link ads_image ads_sequence')
        .sort('ads_sequence')
        .lean();

        // Add domain to ads_image paths
        ads = ads.map(ad => ({
            ...ad,
            ads_image: `http://api.aguli.in${ad.ads_image}`
        }));

        // Calculate total pages
        const totalPages = Math.ceil(totalCount / limit);

        return res.status(200).json({
            success: true,
            data: {
                news,
                ads,
                pagination: {
                    currentPage: page,
                    totalPages,
                    totalItems: totalCount,
                    hasNextPage: page < totalPages,
                    hasPrevPage: page > 1
                }
            }
        });

    } catch (error) {
        console.error('Get News By Category Error:', error);
        return res.status(500).json({
            success: false,
            message: 'Server error',
            error: error.message
        });
    }
};

exports.getAllExplore = async (req, res) => {
    try {
        // Get page from query params, default to 1 if not provided
        const page = parseInt(req.query.page) || 1;
        const limit = 10; // Fixed limit of 10 items per page

        // Calculate skip value for pagination
        const skip = (page - 1) * limit;

        // Get total count of documents
        const total = await ExploreModel.countDocuments();

        // Get paginated explore posts
        const explorePosts = await ExploreModel.find()
            .sort({ createdAt: -1 }) // Fixed field name
            .skip(skip)
            .limit(limit)
            .lean(); // Add lean() for better performance

        // Get ads for explore screen
        let ads = await AdsModel.find({
            ads_screen: 'explore',
            ads_status: 'active'
        })
        .select('ads_type ads_link ads_image ads_sequence')
        .sort('ads_sequence')
        .lean();

        // Add domain to ads_image paths
        ads = ads.map(ad => ({
            ...ad,
            ads_image: `http://api.aguli.in${ad.ads_image}`
        }));

        return res.status(200).json({
            success: true,
            message: 'Explore posts fetched successfully',
            data: {
                explorePosts,
                ads,
                pagination: {
                    currentPage: page,
                    totalPages: Math.ceil(total / limit),
                    totalItems: total,
                    itemsPerPage: limit,
                    hasNextPage: page < Math.ceil(total / limit),
                    hasPrevPage: page > 1
                }
            }
        });
    } catch (err) {
        console.error('Error fetching explore posts:', err);
        return res.status(500).json({
            success: false,
            message: 'Server error',
            error: err.message
        });
    }
};
