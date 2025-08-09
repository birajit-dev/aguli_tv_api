const { request } = require('express');
var express = require('express');
require('../model/database');

const { resolve } = require('path');
const { all } = require('express/lib/application');
const { assert } = require('console');

const NewsModel = require('../model/ainews');


exports.getNewsByCategory = async (req, res) => {
    try {
        const category = req.query.category;
        const page = parseInt(req.query.page) || 1;
        const limit = 10; // Number of items per page
        const skip = (page - 1) * limit;
        const domain = "http://api.aguli.in" // Get domain from query params

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
            update_date: new Date(item.update_date).toISOString()
        }));

        // Calculate total pages
        const totalPages = Math.ceil(totalCount / limit);

        return res.status(200).json({
            success: true,
            data: {
                news,
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


exports.getNewsbyId = async (req, res) => {
    try {
        const newsId = req.query.id;
        const domain = "http://api.aguli.in";

        // Get the main news article
        const news = await NewsModel.findById(newsId)
            .select('post_name post_url post_description post_content post_keyword post_category post_image meta_tags author_key author_name post_status image_source update_date')
            .lean();
        
        if (!news) {
            return res.status(404).json({
                success: false,
                message: 'News not found'
            });
        }

        // Format update_date to match required format
        news.update_date = new Date(news.update_date).toISOString();

        // Add domain to image path
        news.post_image = domain ? `${domain}${news.post_image}` : news.post_image;

        // Get 10 related news from same category
        const relatedNews = await NewsModel.find({
            _id: { $ne: newsId }, // Exclude current article
            post_category: news.post_category,
            post_status: 'Published'
        })
        .sort({ update_date: -1 })
        .limit(10)
        .select('post_name post_url post_description post_image update_date author_name post_category')
        .lean();

        // Get latest news from other categories
        const otherNews = await NewsModel.find({
            post_category: { $ne: news.post_category },
            post_status: 'Published'
        })
        .sort({ update_date: -1 })
        .limit(10)
        .select('post_name post_url post_description post_image update_date author_name post_category')
        .lean();

        // Add domain to image paths for related and other news
        const formatNews = (articles) => {
            return articles.map(item => ({
                ...item,
                post_image: domain ? `${domain}${item.post_image}` : item.post_image,
                update_date: new Date(item.update_date).toISOString()
            }));
        };

        return res.status(200).json({
            success: true,
            data: {
                news,
                relatedNews: formatNews(relatedNews),
                otherNews: formatNews(otherNews)
            }
        });

    } catch (err) {
        console.error('Error fetching news:', err);
        return res.status(500).json({
            success: false,
            message: 'Server error',
            error: err.message
        });
    }
};