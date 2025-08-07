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
const AiNewsModel = require('../model/ainews');
const DocumentModel = require('../model/document');
const ImageModel = require('../model/images');
const CategoryModel = require('../model/category');
const ProfileModel = require('../model/profile');
const VideoModel = require('../model/video');
const ExploreModel = require('../model/explore');
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
const serviceAccount = require('./aguli-tv-firebase-adminsdk-fbsvc-982ae0adec.json'); // Firebase service account file in public folder

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});





    //Multer Outside



    const newDate = moment().format('lll');





    //Random Function
    function getRandomInt(max) {
        return Math.floor(Math.random() * Math.floor(max));
    };

      

    exports.adminLogin = async(req, res) => {
        res.render('admin/login',{
            layout:''
        });
    }

    exports.addNews = async(req, res) =>{
        adminSession=req.session;
            if(!adminSession.userid){
                res.redirect('/admin/user/login');
            }
            else{
                res.render('admin/addnews',{
                    title:'Northeast Herald',
                    layout: ''
                    })
            }
    }

    exports.authAdmin = async(req, res) => {
        const { username, password } = req.body;
        const user = await adminData.findOne({username}).lean();
        console.log(user);
        if(!user){
            return res.redirect('/error');
        }
        const matchPass = await bcrypt.compare(password, user.password);
        if(!matchPass){
            return res.send("alert('Password does not match motherfucker')");
        }else{
            var adminSession = req.session;
            adminSession.userid = username;
            //req.session.authA = username;
            //var fuckingA = req.session.authA;
            //session.userid=user.username;
            res.redirect('/admin/user/dashboard');
        }
    }

   




    exports.upImage = async(req, res) =>{
        upload(req, res, function(err){
            if(err){
                res.send('Image Can not Upload.');
            }else{
                //console.log(req.file);
                res.send('Image Uploaded.');
                const file = req.file.filename;
                    let saveImage = new singleUp({
                        image_path: file
                    });
                saveImage.save();
            }
        });
    }


   


   
    

   

   

 

   

    exports.brNews = async(req, res, next) =>{
        const {title, keyword} = req.body;        
        let brurl = title.toLowerCase().replace(/ /g, '-').replace(/[^\w-]+/g, '');
        console.log(title, keyword, brurl)
        let breakingnews = new breakingNews({
            breaking_title:title,
            breaking_keyword:keyword,
            breaking_url:brurl,
            update_date:newDate,
        });
        breakingnews.save();
        res.send("Breaking News Uploaded.")
    }

    exports.listBreaking = async(req, res, next) =>{
            adminSession=req.session;
            if(!adminSession.userid){
                res.redirect('/admin/user/login');
            }
            else{
            const brdata = await breakingNews.find().sort({brnews:-1}).lean();
            res.render('admin/listbreaking',{
                layout:'',
                brdata
            });
            }
    }

    exports.editBreaking = async(req, res) =>{
        adminSession=req.session;
        if(!adminSession.userid){
            res.redirect('/admin/user/login');
        }
        else{
        let pid = req.params.id;
        const edbreaking = await breakingNews.findOne({brnews_id:pid}).lean();
        res.render('admin/editbreaking',{
            layout:'',
            edbreaking
        });
        }
    }

    exports.updateBreaking = async(req, res) => {
        const {title, keyword, id} = req.body;
        let brurl = title.toLowerCase().replace(/ /g, '-').replace(/[^\w-]+/g, '');
        breakingNews.findByIdAndUpdate(id, 
            {
                breaking_title: title,
                breaking_keyword: keyword,
                breaking_url: brurl,
                update_date:newDate,
            },function(err, data) {
            if(err){
                res.send('Something Went Wrong');
            }
            else{
                res.send('Breaking News Update Successfully.');
            }
            });
    }

    exports.breakingPage = async(req, res, next) =>{
        try{
            res.render('admin/addbreaking',{
                layout: '',
            })
        }catch{

        }
    }

    

    exports.deleteBreaking = async(req, res, next) =>{
        let idd = req.params.id;
            breakingNews.remove({_id:idd}, 
            function(err, data) {
                if(err){
                    res.send("Can not Delete");
                }
                else{
                    res.redirect('/admin/user/listbreaking');
                }
            });  
    }

    exports.deleteGallery = async(req, res, next) =>{
        let idd = req.params.id;
            galleryDb.remove({_id:idd}, 
            function(err, data) {
                if(err){
                    res.send("Can not Delete");
                }
                else{
                    res.redirect('/admin/user/dashboard');
                }
            });  
    }

   


    exports.addInsideUsers = async(req, res, next) =>{
        try{
            const {user_mail,user_role,user_pic,login_pass,user_name} = req.body;
            var user_status = 'Active';
            
            let upUserRole = new UserRoles({
                user_mail:user_mail,
                user_name:user_name,
                user_role:user_role,
                user_status:user_status,
                user_pic:user_pic,
                login_id:user_mail,
                login_pass:login_pass,
            });
            const sse = upUserRole.save();
            res.redirect('/admin/user/allusers');
        }catch(error){
            res.status(400).json({message: error.message});
        }
    }
    exports.addUserPage = async(req, res)=>{
        try{
            res.render('admin/adduser',{
                layout: '',
            })
        }catch{

        }
    }

    exports.addAuthor = async(req, res) =>{

        const characters ='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        function generateString(length) {
        let result = '';
        const charactersLength = characters.length;
        for ( let i = 0; i < length; i++ ) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
        }
        const ab =  req.body;
        const addauthor = new UserModel({
            user_mail: ab.user_mail,
            user_name: ab.user_name,
            user_role: ab.user_role,
            user_status: ab.user_status,
            user_pic: ab.user_pic,
            login_id: ab.login_id,
            password: ab.password,
            author_bio: ab.author_bio,
            update_date: newDate,
            facebook_link: ab.facebook_link,
            twitter_link: ab.twitter_link,
            instagram_link: ab.instagram_link,
            linkedin_link: ab.linkedin_link,
            tag_line: ab.tag_line,
            domain_owner: ab.domain_owner,
            domain_key: ab.domain_key,
            domain_name: ab.domain_name,
            author_code: generateString(6),
            update_date: String

        });
        await addauthor.save();
        res.send("User Added Successfully");
    }

    exports.addMedia = async(req, res) =>{
        const ranDom = getRandomInt(999999);
        const upload = multer({ 
            storage: multerS3({
            s3: s3,
            bucket: 'birdev',
            acl: 'public-read',
            key: function (request, file, cb) {
                console.log(file);
                cb(null,'news/'+ranDom + file.originalname);
            }
            })
        }).single('myFile', 1);

        upload(req, res, function(err){
            if(err){
                res.send('Something Went Wrong');
            }else{
                //console.log(req.file);
                const filex = req.file.originalname;
                const nFile = ranDom +filex;
                const urlp = "https://birdev.blr1.cdn.digitaloceanspaces.com/news/";
                const aFile = urlp +nFile;
                const nDate = moment().format('lll');
                let mediaAdd = new MediaModel({
                    media_path:aFile,
                    media_alt:"Kokthum news image",
                    update_date:newDate,
                });
                mediaAdd.save();
                res.send("Media Uploaded.")
            }
        });   
    }



    exports.allUsers = async(req, res) =>{
        adminSession=req.session;
            if(!adminSession.userid){
                res.redirect('/admin/user/login');
            }
            else{
            const allUsers = await UserModel.find().sort({user_id:-1}).lean();
            res.render('admin/userlist',{
                layout:'',
                allUsers
            });
            }
    }
    
    exports.editAuthorPage = async(req, res) =>{
        adminSession=req.session;
            if(!adminSession.userid){
                res.redirect('/admin/user/login');
            }
            else{
            let pid = req.query.id;
            const edAuthor = await UserModel.findById({_id:pid}).lean();
            res.render('admin/editAuthor',{
                layout:'',
                edAuthor
            });
            }
    }


    exports.updateAuthor = async (req, res) => {
        const updatedData = req.body;
        console.log(updatedData.userId);
    
        try {        
    
            // Use findByIdAndUpdate to update the user by ID
            const updatedUser = await UserModel.findByIdAndUpdate(updatedData.userId,
                {
                    $set: {
                        user_mail: updatedData.user_mail,
                        user_name: updatedData.user_name,
                        user_role: updatedData.user_role,
                        user_status: updatedData.user_status,
                        user_pic: updatedData.user_pic,
                        login_id: updatedData.login_id,
                        password: updatedData.password,
                        author_bio: updatedData.author_bio,
                        update_date: new Date(),
                        facebook_link: updatedData.facebook_link,
                        twitter_link: updatedData.twitter_link,
                        instagram_link: updatedData.instagram_link,
                        linkedin_link: updatedData.linkedin_link,
                        tag_line: updatedData.tag_line,
                        // Note: The author_code field is not updated, as it's typically a static value for an author.
                    },
                },
                { new: true } // Return the updated document
            );
    
            if (!updatedUser) {
                return res.status(404).json({ message: 'User not found' });
            }
    
            res.json({ message: 'User updated successfully', user: updatedUser });
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Server error' });
        }
    };
    


    //Fetching News List for Admin User
    exports.AdminNewsList = async (req, res) => {
        try {
          const page = parseInt(req.query.page) || 1;
          const KEY = req.query.key;
          const search = req.query.search || '';
          const limit = 20;
          const skip = (page - 1) * limit;
      
          if (!KEY) {
            return res.status(400).json({ success: false, message: "Missing SaaS key" });
          }
      
          // Build filter
          const filter = {
            domain_key: KEY,
            post_status: 'Published'
          };
      
          // If search is present, add case-insensitive search on post_name or post_description
          if (search) {
            filter.$or = [
              { post_name: { $regex: search, $options: 'i' } },
              { post_description: { $regex: search, $options: 'i' } }
            ];
          }
      
          const totalPosts = await AiNewsModel.countDocuments(filter);
          const totalPages = Math.ceil(totalPosts / limit);
      
          const dashAllNews = await AiNewsModel.find(filter)
            .sort({ ai_seq: -1 })
            .skip(skip)
            .limit(limit)
            .lean();
      
          res.json({
            success: true,
            data: {
              news: dashAllNews,
              pagination: {
                currentPage: page,
                totalPages,
                totalPosts,
                limit,
                hasNextPage: page < totalPages,
                hasPrevPage: page > 1,
                nextPage: page + 1,
                prevPage: page - 1
              }
            }
          });
        } catch (error) {
          console.error("AdminNewsList Error:", error);
          res.status(500).json({
            success: false,
            message: "Error fetching news list",
            error: error.message
          });
        }
      };
      
    //Fetching Author List for Admin User
    exports.authorList = async(req, res) => {
        try {
            const KEY = req.query.key;
            const allUsers = await UserModel.find({domain_key: KEY}).sort({user_id:-1}).lean();
            res.json({
                success: true,
                data: {
                    authors: allUsers
                }
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                error: error.message || "Error fetching author list"
            });
        }
    }

    //Fetching Image Gallery for Admin User

    exports.ImageGallery = async (req, res) => {
        try {
            const APIKEY = req.query.key;
            const page = parseInt(req.query.page) || 1; // Default page 1
            const limit = 20; // Items per page
            const skip = (page - 1) * limit; // Offset calculation

            if (!APIKEY) {
                return res.status(400).json({ message: 'Missing saasAPI key in request body' });
            }
        
            // Fetch SaaS user based on saasAPI
            const getAPI = await SaasUserModel.findOne({ saas_api: APIKEY });
    
            if (!APIKEY) {
            return res.status(404).json({ message: 'Invalid saasAPI or user not found' });
            }
            // Fetch images from ImageModel
            const imageGallery = await ImageModel.find({domain_key: APIKEY}, { file_name: 1, file_path: 1, uploaded_date: 1, _id: 0 })
                .sort({ uploaded_date: -1 });
            // Fetch images from allNews model
            const newsImages = await AiNewsModel.find({}, { post_image: 1, update_date: 1, _id: 0 })
                .sort({ update_date: -1 });
            // Format news images properly
            const formattedNewsImages = newsImages.map(img => ({
                file_name: img.post_image.split('/').pop(), // Extract file name
                file_path: img.post_image, // Already stored path
                uploaded_date: img.update_date
            }));
            // Merge both image sources
            const allImages = [...imageGallery, ...formattedNewsImages];
            // Sort all images by upload date (latest first)
            allImages.sort((a, b) => new Date(b.uploaded_date) - new Date(a.uploaded_date));
            // Paginate results
            const totalImages = allImages.length;
            const totalPages = Math.ceil(totalImages / limit);
            const paginatedImages = allImages.slice(skip, skip + limit);
            res.status(200).json({
                currentPage: page,
                totalPages,
                totalImages,
                images: paginatedImages
            });

        } catch (error) {
            console.error("Image Gallery Error:", error);
            res.status(500).json({ message: "Server Error", error: error.message });
        }
    };


    //Add News by Admin User for Particular Domain
    exports.AddNewsAdmin = async (req, res) => {
        try {
          if (!req.file) {
            return res.status(400).json({ message: 'Image file is required' });
          }
      
          const filePath = "/uploads/news/" + req.file.filename;
      
          const { post_name,post_description,post_content,post_keyword,post_category,meta_tags,author_key,author_name,domain_owner,domain_key,domain_name,top_news,
            editorial_news,
            headline_news,
            breaking_news,
            optional_1,
            optional_2,
            optional_3,
            optional_4,
            image_source,
            post_status,
          } = req.body;
      
          const purl = post_name.toLowerCase().replace(/ /g, '-').replace(/[^\w-]+/g, '');
      
          const newNews = new AiNewsModel({
            post_name,
            post_url: purl,
            post_description,
            post_content,
            post_keyword,
            post_category,
            post_image: filePath,
            meta_tags,
            author_key,
            author_name,
            post_status,
            domain_owner,
            domain_key,
            domain_name,
            top_news,
            editorial_news,
            headline_news,
            breaking_news,
            optional_1,
            optional_2,
            optional_3,
            optional_4,
            image_source,
            update_date: new Date(),
          });
          await newNews.save();
	  try {
            await axios.post('https://kokthum.com/send', {
                title: `📰 ${post_name}`,
                message: post_description || 'A new post just dropped!', 
                //message: post_description ' | Click to Read More', 
                url: `https://kokthum.com/${post_category}/${purl}`
            });
          } catch (error) {
              console.error('Error sending notification:', error);
              // Continue execution even if notification fails
          }
          return res.status(200).json({ message: 'News posted successfully' });
        } catch (err) {
          console.error('AddNewsAdmin Error:', err);
          return res.status(500).json({ message: 'Failed to save news', error: err.message });
        }
    };


    exports.uploadDocument = async (req, res) => {
    req.uploadMiddleware(req, res, async (err) => {

        

        try {
            const { saasAPI } = req.body;

        if (!saasAPI) {
        return res.status(400).json({ message: 'Missing saasAPI key in request body' });
        }

        // Fetch SaaS user based on saasAPI
        const getAPI = await SaasUserModel.findOne({ saas_api: saasAPI });

        if (!getAPI) {
        return res.status(404).json({ message: 'Invalid saasAPI or user not found' });
        }

        console.log(getAPI);

        if (err) {
        return res.status(400).json({ message: err.message });
        }

        if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
        }

        const filePath = `/uploads/documents/${req.file.filename}`;

        // Insert into the database
        const newDocument = new DocumentModel({
            file_name: req.file.originalname,
            file_path: filePath,
            domain_owner: getAPI.saas_user,
            domain_key: getAPI.saas_api,
            domain_name: getAPI.saas_domain,
            uploaded_date: new Date(),
        });

        await newDocument.save();

        res.status(200).json({
            message: 'File uploaded successfully',
            filePath,
        });

        } catch (dbError) {
        console.error('Database Insertion Error:', dbError);
        res.status(500).json({ message: 'Failed to save document info', error: dbError.message });
        }
    });
    };

    exports.getDocuments = async (req, res) => {
        try {

            const APIKEY = req.query.key;
            if (!APIKEY) {
                return res.status(400).json({ message: 'Missing saasAPI key in request body' });
            }
            // Fetch SaaS user based on saasAPI
            const getAPI = await SaasUserModel.findOne({ saas_api: APIKEY });
            if (!getAPI) {
            return res.status(404).json({ message: 'Invalid saasAPI or user not found' });
            }

          const documents = await DocumentModel.find({domain_key: getAPI.saas_api}).sort({ uploaded_date: -1 }); // Sort by latest uploaded
          res.status(200).json({
            message: 'Documents fetched successfully',
            documents,
          });
        } catch (error) {
          console.error('Fetch Documents Error:', error);
          res.status(500).json({ message: 'Failed to fetch documents', error: error.message });
        }
      };


      
      exports.deleteDocument = async (req, res) => {
        try {
          const document = await DocumentModel.findById(req.params.id);
      
          if (!document) {
            return res.status(404).json({ message: 'Document not found' });
          }
      
          // Corrected file path using `path.join` (ensuring it points to the correct directory)
          const filePath = path.join(__dirname, '..', 'public', document.file_path);
      
          // Check if file exists before attempting to delete
          if (fs.existsSync(filePath)) {
            fs.unlink(filePath, async (err) => {
              if (err) {
                console.error('File Deletion Error:', err);
                return res.status(500).json({ message: 'Failed to delete file from storage' });
              }
      
              // Delete document record from DB
              await DocumentModel.findByIdAndDelete(req.params.id);
              return res.status(200).json({ message: 'Document deleted successfully' });
            });
          } else {
            console.warn('File not found in storage, deleting only from DB');
            await DocumentModel.findByIdAndDelete(req.params.id);
            return res.status(200).json({ message: 'Document record deleted (file was already missing)' });
          }
      
        } catch (error) {
          console.error('Delete Document Error:', error);
          res.status(500).json({ message: 'Failed to delete document', error: error.message });
        }
      };


    exports.uploadImage = async (req, res) => {
    try {

        const { saasAPI } = req.body;

        if (!saasAPI) {
        return res.status(400).json({ message: 'Missing saasAPI key in request body' });
        }

        // Fetch SaaS user based on saasAPI
        const getAPI = await SaasUserModel.findOne({ saas_api: saasAPI });

        if (!getAPI) {
        return res.status(404).json({ message: 'Invalid saasAPI or user not found' });
        }
        
        if (!req.file) {
        return res.status(400).json({ message: 'No image uploaded' });
        }

        const filePath = `/uploads/images/${req.file.filename}`;

        

        console.log(getAPI.saas_api);

        // Save image details to the database
        const newImage = new ImageModel({
        file_name: req.file.filename,
        file_path: filePath,
        domain_owner: getAPI.saas_user,
        domain_key: getAPI.saas_api,
        domain_name: getAPI.saas_domain,
        });

        await newImage.save();

        return res.status(200).json({
        message: 'Image uploaded successfully',
        fileUrl: filePath // URL to access the image
        });

    } catch (error) {
        console.error('Upload Image Error:', error);
        return res.status(500).json({ message: 'Failed to upload image', error: error.message });
    }
    };



exports.saasUserCreate = async (req, res) => {
  try {
    const {
      saas_user,
      saas_email,
      saas_phone,
      saas_country,
      saas_company_name,
      saas_domain,
      saas_password,
    } = req.body;

    if (!saas_user || !saas_email || !saas_password) {
      return res.status(400).json({ message: 'Required fields missing' });
    }

    // Check if email or domain already exists
    const existingUser = await SaasUserModel.findOne({ 
      $or: [{ saas_email }, { saas_domain }] 
    });

    if (existingUser) {
      return res.status(409).json({ message: 'Email or domain already exists' });
    }

    // 🔐 Hash password
    const hashedPassword = await bcrypt.hash(saas_password, 10);

    // Generate API key and SaaS key
    const saas_api = crypto.randomBytes(24).toString('hex'); // 48 chars
    const saas_key = crypto.randomBytes(16).toString('hex'); // 32 chars
    const createdat = new Date().toISOString();

    const newUser = new SaasUserModel({
      saas_user,
      saas_email,
      saas_phone,
      saas_country,
      saas_company_name,
      saas_domain,
      saas_password: hashedPassword,
      saas_api,
      saas_verify: '0958',
      saas_key,
      createdat,
    });

    await newUser.save();

    return res.status(201).json({
      message: 'SaaS user created successfully',
      data: {
        saas_user,
        saas_email,
        saas_domain,
        saas_api,
        saas_key,
        createdat,
      },
    });
  } catch (err) {   
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
};



    exports.saasUserList = async (req, res) => {
        try {
        // Fetch all users (you can add pagination or filters later)
        const users = await SaasUserModel.find({}, '-saas_password'); // exclude password field
    
        return res.status(200).json({
            message: 'SaaS users fetched successfully',
            count: users.length,
            data: users,
        });
        } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Server error while fetching users' });
        }
    };




    exports.saasUserVerify = async (req, res) => {
      try {
        const { saas_email, verification_code } = req.body;
    
        if (!saas_email || !verification_code) {
          return res.status(400).json({ message: 'Missing required fields' });
        }
    
        // Find user by email
        const user = await SaasUserModel.findOne({ saas_email });
    
        if (!user) {
          return res.status(404).json({ message: 'User not found' });
        }
        
        console.log(user.saas_verify);
        console.log(verification_code);
        // Compare verification_code with saas_verify field
        if (verification_code !== user.saas_verify) {
          return res.status(401).json({ message: 'Invalid verification code' });
        }
    
        // Set saas_verify to 'true'
        user.saas_verify = 'true';
        await user.save();
    
        return res.status(200).json({
          message: 'User verified successfully',
          data: {
            saas_email: user.saas_email,
            saas_verify: user.saas_verify,
          },
        });
    
      } catch (err) {
        console.error('Verification error:', err);
        return res.status(500).json({ message: 'Server error during verification' });
      }
    };





    exports.saasUserAuth = async (req, res) => {
        const { email, password } = req.body;
        try {
            const user = await SaasUserModel.findOne({ saas_email: email });

            if (!user) {
            return res.status(401).json({ message: 'User not found' });
            }
            // Compare bcrypt hash
            const isPasswordValid = await bcrypt.compare(password, user.saas_password);
            if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
            }

            const token = jwt.sign(
            { 
                email: user.saas_email,
                id: user._id,
                saas_user: user.saas_user,   // Include username
                saas_api: user.saas_api,
                saas_domain: user.saas_domain
            },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
            );

            res.status(200).json({
                message: 'Login successful',
                token,
                saas_user: user.saas_user,     // Username
                saas_email: user.saas_email,
                saas_api: user.saas_api,
                saas_key: user.saas_key,
                saas_domain: user.saas_domain
            });
            
        } catch (err) {
            console.error('Auth error:', err);
            res.status(500).json({ message: 'Server error during login' });
        }
    };


    



    //FOR AUTHOR CONTROLLER
    
    
    exports.authorLogin = async (req, res) => {
      try {
        const { login_id, password } = req.body;
        // 1. Validate input
        if (!login_id || !password) {
          return res.status(400).json({ message: 'login_id and password are required' });
        }
    
        // 2. Find user
        const author = await AuthorModel.findOne({ login_id });
    
        if (!author || author.password !== password) {
          return res.status(401).json({ message: 'Invalid credentials' });
        }
    
        // 3. Generate JWT
        const token = jwt.sign(
          {
            id: author._id,
            login_id: author.login_id,
            name: author.user_name,
            authorKey: author.author_code,
            author_domain_owner: author.domain_owner,   // Include username
            author_domain_key: author.domain_key,
            author_domain_name: author.domain_name,
            role: 'author',
          },
          JWT_SECRET,
          { expiresIn: '1d' }
        );    
        // 4. Respond with token
        return res.status(200).json({
          message: 'Login successful',
          token,
          author: {
            id: author._id,
            name: author.user_name,
            authorKey: author.author_code,
            login_id: author.login_id,
            author_domain_owner: author.domain_owner,   // Include username
            author_domain_key: author.domain_key,
            author_domain_name: author.domain_name
          },
        });
    
      } catch (error) {
        console.error('Author Login Error:', error);
        return res.status(500).json({ message: 'Server error', error: error.message });
      }
    };

    exports.getVerifyContent = async (req, res) => {
        try {
          const { key } = req.query;
          const page = parseInt(req.query.page) || 1;
          const limit = parseInt(req.query.limit) || 10;
          const skip = (page - 1) * limit;
      
          if (!key) {
            return res.status(400).json({ message: 'Missing domain key' });
          }
      
          // 1. Fetch total count
          const total = await AiNewsModel.countDocuments({
            domain_key: key,
            post_status: 'Draft',
          });
      
          // 2. Fetch paginated data
          const getNews = await AiNewsModel.find({
            domain_key: key,
            post_status: 'Draft',
          })
            .sort({ update_date: -1 }) // latest first
            .skip(skip)
            .limit(limit)
            .lean();
      
          // 3. Return response
          return res.status(200).json({
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit),
            news: getNews,
          });
        } catch (error) {
          console.error('Error in getVerifyContent:', error);
          return res.status(500).json({ message: 'Server error', error: error.message });
        }
      };

exports.getAuthorArticles = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const KEY = req.query.key;
        const authorKey = req.query.authorKey;
        const limit = 20;
        const skip = (page - 1) * limit;

        // Apply filters to count only posts by that author under the domain
        const filter = { domain_key: KEY, author_key: authorKey };

        const totalPosts = await AiNewsModel.countDocuments(filter);
        const totalPages = Math.ceil(totalPosts / limit);

        const dashAllNews = await AiNewsModel.find(filter)
            .sort({ update_date: -1 })
            .skip(skip)
            .limit(limit)
            .lean();

        res.json({
            success: true,
            data: {
                news: dashAllNews,
                pagination: {
                    currentPage: page,
                    totalPages,
                    totalPosts,
                    limit,
                    hasNextPage: page < totalPages,
                    hasPrevPage: page > 1,
                    nextPage: page + 1,
                    prevPage: page - 1
                }
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message || "Error fetching news list"
        });
    }
}


        exports.approveNews = async (req, res) => {
        try {
            const { id } = req.params;

            const updated = await AiNewsModel.findByIdAndUpdate(
            id,
            { post_status: 'Published', update_date: new Date() },
            { new: true }
            );

            if (!updated) {
            return res.status(404).json({ message: 'News post not found' });
            }

            return res.status(200).json({
            message: 'News post approved successfully',
            data: updated,
            });
        } catch (error) {
            console.error('Approve News Error:', error);
            return res.status(500).json({ message: 'Failed to approve news post', error: error.message });
        }
        };


        // controllers/adminController.js

    exports.getSingleNews = async (req, res) => {
    try {
        const { id } = req.params;
        const { key } = req.query;

        if (!key) {
        return res.status(400).json({ message: 'Missing saasAPI key' });
        }

        // Validate SaaS key
        const saasUser = await SaasUserModel.findOne({ saas_api: key });
        if (!saasUser) {
        return res.status(401).json({ message: 'Invalid saasAPI key' });
        }

        // Fetch news item
        const news = await AiNewsModel.findOne({
        _id: id,
        domain_key: saasUser.saas_api, // ensure only from the right tenant
        }).lean();

        if (!news) {
        return res.status(404).json({ message: 'News not found' });
        }

        return res.status(200).json({
        message: 'News fetched successfully',
        data: news,
        });
    } catch (error) {
        console.error('Get Single News Error:', error);
        return res.status(500).json({ message: 'Server error', error: error.message });
    }
    };



exports.updateNewsById = async (req, res) => {
  try {
    const { id } = req.params;
    const saasAPI = req.query.key;

    if (!saasAPI) {
      return res.status(400).json({ message: "Missing SaaS API key" });
    }

    // Fetch existing news item
    const existingNews = await AiNewsModel.findOne({ _id: id, domain_key: saasAPI });

    if (!existingNews) {
      return res.status(404).json({ message: "News not found" });
    }

    // Handle image: retain old image if new one not uploaded
    const filePath = req.file
      ? "/uploads/news/" + req.file.filename
      : existingNews.post_image;

    // Get updated fields from body
    const {
      post_name,
      post_description,
      post_content,
      post_keyword,
      post_category,
      meta_tags,
      author_key,
      author_name,
      post_status,
      domain_owner,
      domain_key,
      domain_name,
      top_news,
      editorial_news,
      headline_news,
      breaking_news,
      optional_1,
      optional_2,
      optional_3,
      optional_4,
      image_source
    } = req.body;

    // Generate slug safely
    const purl = post_name
      ? post_name.toLowerCase().replace(/ /g, "-").replace(/[^\w-]+/g, "")
      : existingNews.post_url;

    // Update the news
    await AiNewsModel.findByIdAndUpdate(
      id,
      {
        post_name: post_name ?? existingNews.post_name,
        post_url: purl,
        post_description,
        post_content,
        post_keyword,
        post_category,
        post_image: filePath,
        meta_tags,
        author_key,
        author_name,
        post_status,
        domain_owner,
        domain_key,
        domain_name,
        top_news,
        editorial_news,
        headline_news,
        breaking_news,
        optional_1,
        optional_2,
        optional_3,
        optional_4,
        image_source,
        update_date: new Date()
      },
      { new: true }
    );

    return res.status(200).json({ message: "News updated successfully" });
  } catch (err) {
    console.error("UpdateNewsById Error:", err);
    return res.status(500).json({ message: "Failed to update news", error: err.message });
  }
};



exports.deleteNewsById = async (req, res) => {
  try {
    const { id } = req.params;
    const { key } = req.query;

    if (!id || !key) {
      return res.status(400).json({ message: "Missing news ID or SaaS API key" });
    }

    const news = await AiNewsModel.findOne({ _id: id, domain_key: key });

    if (!news) {
      return res.status(404).json({ message: "News not found or unauthorized access" });
    }

    await AiNewsModel.deleteOne({ _id: id });

    return res.status(200).json({ message: "News deleted successfully" });
  } catch (err) {
    console.error("DeleteNewsById Error:", err);
    return res.status(500).json({ message: "Failed to delete news", error: err.message });
  }
};


      


      
    







exports.updateAuthorAI = async (req, res) => {
    try {
        const authorId = req.params.id;
        const updatedData = req.body;
  
        // Optional: generateString for other use if needed
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        function generateString(length) {
            let result = '';
            for (let i = 0; i < length; i++) {
                result += characters.charAt(Math.floor(Math.random() * characters.length));
            }
            return result;
        }
  
        updatedData.update_date = new Date();
  
        const updatedAuthor = await UserModel.findByIdAndUpdate(authorId, {
            $set: {
                user_mail: updatedData.user_mail,
                user_name: updatedData.user_name,
                user_role: updatedData.user_role,
                user_status: updatedData.user_status,
                user_pic: updatedData.user_pic,
                login_id: updatedData.login_id,
                password: updatedData.password,
                author_bio: updatedData.author_bio,
                facebook_link: updatedData.facebook_link,
                twitter_link: updatedData.twitter_link,
                instagram_link: updatedData.instagram_link,
                linkedin_link: updatedData.linkedin_link,
                tag_line: updatedData.tag_line,
                update_date: updatedData.update_date,
                // Do NOT update domain_owner, domain_key, or domain_name
            }
        }, { new: true });
  
        if (!updatedAuthor) {
            return res.status(404).json({ message: 'Author not found' });
        }
  
        res.status(200).json({ message: 'Author updated successfully', author: updatedAuthor });
  
    } catch (err) {
        console.error('Error updating author:', err);
        res.status(500).json({ message: 'Server error' });
    }
  };

  exports.deleteAuthorAI = async (req, res) => {
    try {
        const authorId = req.params.id;

        if (!authorId) {
            return res.status(400).json({ message: 'Author ID is required' });
        }

        const deletedAuthor = await UserModel.findByIdAndDelete(authorId);

        if (!deletedAuthor) {
            return res.status(404).json({ message: 'Author not found' });
        }

        res.status(200).json({ message: 'Author deleted successfully' });
    } catch (err) {
        console.error('Error deleting author:', err);
        res.status(500).json({ message: 'Server error' });
    }
};



//Add new features for Aguli TV 
exports.addCategory = async (req, res) => {
    try {
        const { cat_name, cat_status, cat_order, cat_thumb } = req.body;

        // Generate cat_slug from cat_name (lowercase, replace spaces with hyphens, remove non-alphanumerics except hyphens)
        const cat_slug = cat_name
            .toLowerCase()
            .trim()
            .replace(/[^a-z0-9\s-]/g, '')
            .replace(/\s+/g, '-');

        // Generate cat_code from cat_name (e.g., first 3 letters uppercased + random 3 digits)
        const baseCode = cat_name
            .replace(/[^a-zA-Z0-9]/g, '')
            .substring(0, 3)
            .toUpperCase();
        const randomDigits = Math.floor(100 + Math.random() * 900); // 3 random digits
        const cat_code = `${baseCode}${randomDigits}`;

        const newCategory = new CategoryModel({
            cat_name,
            cat_code,
            cat_thumb,
            cat_slug,
            cat_status,
            cat_order,
            update_date: moment().format('lll'),
        });
        await newCategory.save();
        res.status(200).json({ message: 'Category added successfully', category: newCategory });
    } catch (err) {
        console.error('Error adding category:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.editCategory = async (req, res) => {
    try {
        const { cat_id } = req.params;
        const { cat_name, cat_status, cat_order } = req.body;

        // Find the category by cat_id
        const category = await CategoryModel.findOne({ _id: cat_id });
        if (!category) {
            return res.status(404).json({ message: 'Category not found' });
        }

        // Update fields if provided
        if (cat_name) {
            category.cat_name = cat_name;
            // Update cat_slug if cat_name changes
            category.cat_slug = cat_name
                .toLowerCase()
                .trim()
                .replace(/[^a-z0-9\s-]/g, '')
                .replace(/\s+/g, '-');
            // Optionally update cat_code if you want it to change with name
            const baseCode = cat_name
                .replace(/[^a-zA-Z0-9]/g, '')
                .substring(0, 3)
                .toUpperCase();
            const randomDigits = Math.floor(100 + Math.random() * 900);
            category.cat_code = `${baseCode}${randomDigits}`;
        }
        if (cat_status) category.cat_status = cat_status;
        if (cat_order !== undefined) category.cat_order = cat_order;

        category.update_date = moment().format('lll');

        await category.save();

        res.status(200).json({ message: 'Category updated successfully', category });
    } catch (err) {
        console.error('Error editing category:', err);
        res.status(500).json({ message: 'Server error' });
    }
};


exports.deleteCategory = async (req, res) => {
    try {
        const { cat_id } = req.params;
        const deletedCategory = await CategoryModel.findOneAndDelete({ _id: cat_id });
        if (!deletedCategory) {
            return res.status(404).json({ message: 'Category not found' });
        }
        res.status(200).json({ message: 'Category deleted successfully' });
    } catch (err) {
        console.error('Error deleting category:', err);
        res.status(500).json({ message: 'Server error' });
    }
};


exports.getCategory = async (req, res) => {
    try {
        const categories = await CategoryModel.find().sort({ cat_order: 1 });
        res.status(200).json({ message: 'Categories fetched successfully', categories });
    } catch (err) {
        console.error('Error fetching categories:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.getCategoryMobile = async (req, res) => {
    try {
        const categories = await CategoryModel.find()
            .sort({ cat_order: 1 })
            .select('cat_slug');
        // Map categories to just their names in lowercase
        const categoryNames = categories.map(cat => cat.cat_slug.toLowerCase());

        res.status(200).json({
            success: true,
            data: categoryNames
        });
    } catch (err) {
        console.error('Error fetching categories:', err);
        res.status(500).json({ 
            success: false,
            message: 'Server error' 
        });
    }
};



//Video Controller
// Configure multer storage for video and thumbnail uploads
const videoStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = file.fieldname === 'video' ? 'public/uploads/videos' : 'public/uploads/thumbnails';
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const videoUpload = multer({
    storage: videoStorage,
    fileFilter: (req, file, cb) => {
        if (file.fieldname === "video") {
            if (file.mimetype.startsWith('video/')) {
                cb(null, true);
            } else {
                cb(new Error('Not a video file'));
            }
        } else if (file.fieldname === "thumbnail") {
            if (file.mimetype.startsWith('image/')) {
                cb(null, true);
            } else {
                cb(new Error('Not an image file'));
            }
        }
    }
}).fields([
    { name: 'video', maxCount: 1 },
    { name: 'thumbnail', maxCount: 1 }
]);

exports.createVideo = async (req, res) => {
    try {
        videoUpload(req, res, async (err) => {
            if (err) {
                return res.status(400).json({ message: err.message });
            }

            const {
                video_tittle,
                video_description,
                video_url,
                video_cat,
                video_status,
                thumbnail_url
            } = req.body;

            // Generate video_key
            const baseKey = video_tittle
                .replace(/[^a-zA-Z0-9]/g, '')
                .substring(0, 3)
                .toUpperCase();
            const randomDigits = Math.floor(100 + Math.random() * 900);
            const video_key = `${baseKey}${randomDigits}`;

            let finalVideoUrl = video_url;
            let finalThumbUrl = thumbnail_url;

            // If files were uploaded, use their paths instead of URLs
            if (req.files) {
                if (req.files.video) {
                    finalVideoUrl = `/uploads/videos/${req.files.video[0].filename}`;
                }
                if (req.files.thumbnail) {
                    finalThumbUrl = `/uploads/thumbnails/${req.files.thumbnail[0].filename}`;
                }
            }

            const video = new VideoModel({
                video_tittle,
                video_description,
                video_key,
                video_url: finalVideoUrl,
                video_cat,
                video_thumb: finalThumbUrl,
                video_status,
                video_date: moment().format('lll'),
                video_views: '0',
                video_likes: '0',
                video_comments: '0',
                createdat: moment().format('lll')
            });

            await video.save();
            res.status(201).json({ message: 'Video created successfully', video });
        });
    } catch (err) {
        console.error('Error creating video:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.updateVideo = async (req, res) => {
    try {
        videoUpload(req, res, async (err) => {
            if (err) {
                return res.status(400).json({ message: err.message });
            }

            const { video_id } = req.params;
            const {
                video_tittle,
                video_description,
                video_url,
                video_cat,
                video_status,
                thumbnail_url
            } = req.body;

            const video = await VideoModel.findById(video_id);
            if (!video) {
                return res.status(404).json({ message: 'Video not found' });
            }

            if (video_tittle) {
                video.video_tittle = video_tittle;
                // Update video_key if title changes
                const baseKey = video_tittle
                    .replace(/[^a-zA-Z0-9]/g, '')
                    .substring(0, 3)
                    .toUpperCase();
                const randomDigits = Math.floor(100 + Math.random() * 900);
                video.video_key = `${baseKey}${randomDigits}`;
            }

            if (video_description) video.video_description = video_description;
            if (video_cat) video.video_cat = video_cat;
            if (video_status) video.video_status = video_status;

            // Handle video update
            if (req.files && req.files.video) {
                // Delete old video file if it exists and is local
                if (video.video_url && video.video_url.startsWith('/uploads/')) {
                    const oldPath = path.join('public', video.video_url);
                    if (fs.existsSync(oldPath)) {
                        fs.unlinkSync(oldPath);
                    }
                }
                video.video_url = `/uploads/videos/${req.files.video[0].filename}`;
            } else if (video_url) {
                video.video_url = video_url;
            }

            // Handle thumbnail update
            if (req.files && req.files.thumbnail) {
                // Delete old thumbnail if it exists and is local
                if (video.video_thumb && video.video_thumb.startsWith('/uploads/')) {
                    const oldPath = path.join('public', video.video_thumb);
                    if (fs.existsSync(oldPath)) {
                        fs.unlinkSync(oldPath);
                    }
                }
                video.video_thumb = `/uploads/thumbnails/${req.files.thumbnail[0].filename}`;
            } else if (thumbnail_url) {
                video.video_thumb = thumbnail_url;
            }

            await video.save();
            res.status(200).json({ message: 'Video updated successfully', video });
        });
    } catch (err) {
        console.error('Error updating video:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.deleteVideo = async (req, res) => {
    try {
        const { id } = req.params;
        const video = await VideoModel.findById(id);
        
        if (!video) {
            return res.status(404).json({ message: 'Video not found' });
        }

        // Delete associated files if they exist and are local
        if (video.video_url && video.video_url.startsWith('/uploads/')) {
            const videoPath = path.join('public', video.video_url);
            if (fs.existsSync(videoPath)) {
                fs.unlinkSync(videoPath);
            }
        }

        if (video.video_thumb && video.video_thumb.startsWith('/uploads/')) {
            const thumbPath = path.join('public', video.video_thumb);
            if (fs.existsSync(thumbPath)) {
                fs.unlinkSync(thumbPath);
            }
        }

        await VideoModel.findByIdAndDelete(id);
        res.status(200).json({ message: 'Video deleted successfully' });
    } catch (err) {
        console.error('Error deleting video:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.getAllVideos = async (req, res) => {
    try {
        const videos = await VideoModel.find();
        res.status(200).json({ message: 'Videos fetched successfully', videos });
    } catch (err) {
        console.error('Error fetching videos:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

exports.getVideoById = async (req, res) => {
    try {
        if (!req.params.id) {
            return res.status(400).json({ message: 'Video ID is required' });
        }

        const { id } = req.params;
        
        if (!id.match(/^[0-9a-fA-F]{24}$/)) {
            return res.status(400).json({ message: 'Invalid video ID format' });
        }

        const video = await VideoModel.findById(id).lean();
        
        if (!video) {
            return res.status(404).json({ message: 'Video not found' });
        }

        // Get 10 recent videos from the same category
        const recentVideos = await VideoModel.find({
            _id: { $ne: id }, // Exclude current video
        })
        .sort({ createdat: -1 })
        .limit(10)
        .lean();

        // Format dates
        video.createdat = new Date(video.createdat).toISOString();
        const formattedRecentVideos = recentVideos.map(video => ({
            ...video,
            createdat: new Date(video.createdat).toISOString()
        }));

        return res.status(200).json({ 
            success: true,
            message: 'Video fetched successfully', 
            data: {
                video,
                recentVideos: formattedRecentVideos
            }
        });

    } catch (err) {
        console.error('Error fetching video:', err);
        return res.status(500).json({ 
            success: false,
            message: 'An error occurred while fetching the video',
            error: err.message 
        });
    }
};


exports.getVideoMobile = async (req, res) => {
    try {
        const { category } = req.query;
        const domain = "https://api.sparkshine.co"; // Add domain for file URLs

        if (!category) {
            return res.status(400).json({
                success: false,
                message: 'Category parameter is required'
            });
        }

        // Get page from query params, default to 1 if not provided
        const page = parseInt(req.query.page) || 1;
        const limit = 10; // Fixed limit of 10 items per page

        // Calculate skip value for pagination
        const skip = (page - 1) * limit;

        // Get total count of documents for this category
        const total = await VideoModel.countDocuments({ video_cat: category });

        // Get paginated videos for the category
        let videos = await VideoModel.find({ video_cat: category })
            .sort({ createdat: -1 })
            .skip(skip)
            .limit(limit)
            .lean(); // Use lean() for better performance

        // Process video URLs and format dates
        videos = videos.map(video => {
            const isYoutubeUrl = video.video_url.includes('youtube.com') || 
                                video.video_url.includes('youtu.be') ||
                                video.video_url.startsWith('http://') ||
                                video.video_url.startsWith('https://');
            
            return {
                ...video,
                video_url: isYoutubeUrl ? video.video_url : `${domain}${video.video_url}`,
                createdat: new Date(video.createdat).toISOString()
            };
        });

        res.status(200).json({
            success: true,
            message: 'Videos fetched successfully',
            data: videos,
            pagination: {
                currentPage: page,
                totalPages: Math.ceil(total / limit),
                totalItems: total,
                itemsPerPage: limit
            }
        });
    } catch (err) {
        console.error('Error fetching videos:', err);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: err.message
        });
    }
};

// Get distinct video categories
exports.getVideoCategories = async (req, res) => {
    try {
        const categories = await VideoModel.distinct('video_cat');
        
        res.status(200).json({
            success: true,
            message: 'Video categories fetched successfully',
            data: categories
        });
    } catch (err) {
        console.error('Error fetching video categories:', err);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: err.message
        });
    }
};


//Controller for Profile
exports.googleSignIn = async (req, res) => {
    try {
        const { googleId, email, full_name, profile_picture } = req.body;

        if (!googleId || !email) {
            return res.status(400).json({
                success: false,
                message: 'Google ID and email are required'
            });
        }

        // Check if user already exists
        let profile = await ProfileModel.findOne({ googleId });

        if (profile) {
            // User exists, return existing profile
            return res.status(200).json({
                success: true,
                message: 'User signed in successfully',
                data: profile
            });
        }

        // Create new user profile
        const user_code = crypto.randomBytes(6).toString('hex');
        
        profile = new ProfileModel({
            googleId,
            email,
            full_name,
            profile_picture: profile_picture || null, // Allow null if no picture provided
            user_code,
            status: 'active',
            createdat: new Date().toISOString()
        });

        await profile.save();

        return res.status(201).json({
            success: true,
            message: 'User profile created successfully',
            data: profile
        });

    } catch (err) {
        console.error('Error in Google sign in:', err);
        return res.status(500).json({
            success: false,
            message: 'An error occurred during sign in',
            error: err.message
        });
    }
};

// Configure multer for profile picture uploads
const profileStorage = multer.diskStorage({
    destination: function(req, file, cb) {
        const uploadDir = 'uploads/profiles';
        // Create directory if it doesn't exist
        if (!fs.existsSync(uploadDir)){
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function(req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const profileUpload = multer({
    storage: profileStorage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: function(req, file, cb) {
        if (!file.originalname.match(/\.(jpg|jpeg|png)$/)) {
            return cb(new Error('Only image files are allowed!'), false);
        }
        cb(null, true);
    }
}).single('profile_picture');

exports.uploadProfilePicture = async (req, res) => {
    try {
        const { googleId } = req.params;

        if (!googleId) {
            return res.status(400).json({
                success: false,
                message: 'Google ID is required'
            });
        }

        profileUpload(req, res, async function(err) {
            if (err instanceof multer.MulterError) {
                return res.status(400).json({
                    success: false,
                    message: 'File upload error',
                    error: err.message
                });
            } else if (err) {
                return res.status(400).json({
                    success: false,
                    message: err.message
                });
            }

            if (!req.file) {
                return res.status(400).json({
                    success: false,
                    message: 'No file uploaded'
                });
            }

            const profile = await ProfileModel.findOneAndUpdate(
                { googleId },
                { profile_picture: req.file.path },
                { new: true }
            );

            if (!profile) {
                // Delete uploaded file if profile not found
                fs.unlinkSync(req.file.path);
                return res.status(404).json({
                    success: false,
                    message: 'Profile not found'
                });
            }

            return res.status(200).json({
                success: true,
                message: 'Profile picture uploaded successfully',
                data: profile
            });
        });

    } catch (err) {
        console.error('Error uploading profile picture:', err);
        return res.status(500).json({
            success: false,
            message: 'An error occurred while uploading profile picture',
            error: err.message
        });
    }
};

exports.getProfile = async (req, res) => {
    try {
        const { googleId } = req.params;

        if (!googleId) {
            return res.status(400).json({
                success: false,
                message: 'Google ID is required'
            });
        }

        const profile = await ProfileModel.findOne({ googleId });

        if (!profile) {
            return res.status(404).json({
                success: false,
                message: 'Profile not found'
            });
        }

        return res.status(200).json({
            success: true,
            message: 'Profile fetched successfully',
            data: profile
        });

    } catch (err) {
        console.error('Error fetching profile:', err);
        return res.status(500).json({
            success: false,
            message: 'An error occurred while fetching the profile',
            error: err.message
        });
    }
};

exports.updateProfile = async (req, res) => {
    try {
        const { googleId } = req.params;
        const updateData = req.body;

        if (!googleId) {
            return res.status(400).json({
                success: false,
                message: 'Google ID is required'
            });
        }

        const profile = await ProfileModel.findOneAndUpdate(
            { googleId },
            updateData,
            { new: true }
        );

        if (!profile) {
            return res.status(404).json({
                success: false,
                message: 'Profile not found'
            });
        }

        return res.status(200).json({
            success: true,
            message: 'Profile updated successfully',
            data: profile
        });

    } catch (err) {
        console.error('Error updating profile:', err);
        return res.status(500).json({
            success: false,
            message: 'An error occurred while updating the profile',
            error: err.message
        });
    }
};

//Controller for Explore
// Configure multer storage for explore image uploads


// Configure multer storage for explore image uploads
const exploreStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/uploads/explore');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
    }
});

const exploreUpload = multer({
    storage: exploreStorage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Not an image file'));
        }
    }
}).array('explore_thumb', 5); // Allow up to 5 images

// Create new explore post
exports.createExplore = async (req, res) => {
    try {
        exploreUpload(req, res, async (err) => {
            if (err) {
                return res.status(400).json({ message: err.message });
            }

            const {
                explore_title,
                explore_descriptions,
                explore_status
            } = req.body;

            // Generate explore slug from title
            const explore_slug = explore_title
                .toLowerCase()
                .replace(/[^a-zA-Z0-9]/g, '-');

            // Get image paths if uploaded
            const explore_thumb = req.files ? req.files.map(file => `/uploads/explore/${file.filename}`) : [];

            const explore = new ExploreModel({
                explore_title,
                explore_descriptions,
                explore_thumb, // Array of image paths
                explore_slug,
                explore_status,
                explore_likes: '0',
                createdat: moment().format('lll')
            });

            await explore.save();
            res.status(201).json({ 
                success: true,
                message: 'Explore post created successfully', 
                data: explore 
            });
        });
    } catch (err) {
        console.error('Error creating explore post:', err);
        res.status(500).json({
            success: false, 
            message: 'Server error',
            error: err.message
        });
    }
};

// Get all explore posts
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
            .sort({ createdat: -1 })
            .skip(skip)
            .limit(limit);

        res.status(200).json({
            success: true,
            message: 'Explore posts fetched successfully',
            data: explorePosts,
            pagination: {
                currentPage: page,
                totalPages: Math.ceil(total / limit),
                totalItems: total,
                itemsPerPage: limit
            }
        });
    } catch (err) {
        console.error('Error fetching explore posts:', err);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: err.message
        });
    }
};


// Delete explore post
exports.deleteExplore = async (req, res) => {
    try {
        const { id } = req.params;
        const explore = await ExploreModel.findByIdAndDelete(id);

        if (!explore) {
            return res.status(404).json({
                success: false,
                message: 'Explore post not found'
            });
        }

        // Delete image file if exists
        if (explore.explore_thumb) {
            const imagePath = path.join('public', explore.explore_thumb);
            if (fs.existsSync(imagePath)) {
                fs.unlinkSync(imagePath);
            }
        }

        res.status(200).json({
            success: true,
            message: 'Explore post deleted successfully'
        });
    } catch (err) {
        console.error('Error deleting explore post:', err);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: err.message
        });
    }
};

// Toggle like on explore post
exports.toggleLike = async (req, res) => {
    try {
        const { id } = req.params;
        const explore = await ExploreModel.findById(id);

        if (!explore) {
            return res.status(404).json({
                success: false,
                message: 'Explore post not found'
            });
        }

        // Convert string to number, increment, and convert back
        const currentLikes = parseInt(explore.explore_likes || '0');
        explore.explore_likes = (currentLikes + 1).toString();

        await explore.save();

        res.status(200).json({
            success: true,
            message: 'Like updated successfully',
            data: explore
        });
    } catch (err) {
        console.error('Error updating like:', err);
        res.status(500).json({
            success: false,
            message: 'Server error',
            error: err.message
        });
    }
};


//Controller for Push Notifications
// Send push notification to all users

exports.sendPushNotification = async (req, res) => {
    try {
        const { 
            title, 
            body, 
            screen,
            news_id, // or use news_slug
            thumbnail_url 
        } = req.body;

        if (!title || !body || !news_id) {
            return res.status(400).json({
                success: false,
                message: 'Title, body, and news ID are required for push notification'
            });
        }

        const message = {
            notification: {
                title,
                body,
                imageUrl: thumbnail_url || null
            },
            data: {
                click_action: 'FLUTTER_NOTIFICATION_CLICK',
                screen: screen || 'newsDetails',
                news_id: news_id,
                thumbnail_url: thumbnail_url || '',
                timestamp: new Date().toISOString()
            },
            android: {
                priority: 'high',
                notification: {
                    clickAction: 'FLUTTER_NOTIFICATION_CLICK',
                    imageUrl: thumbnail_url || null,
                    style: 'BIGTEXT',
                    channelId: 'news_channel'
                }
            },
            topic: 'all'
        };

        await admin.messaging().send(message);

        res.status(200).json({
            success: true,
            message: 'Push notification sent successfully to all users'
        });

    } catch (err) {
        console.error('Error sending push notification:', err);
        res.status(500).json({
            success: false,
            message: 'Error sending push notification',
            error: err.message
        });
    }
};


//Controller for LiveTV

// Add Live TV Channel
exports.addLiveTV = async (req, res) => {
    try {
        const { live_tv_name, live_tv_link } = req.body;

        if (!live_tv_name || !live_tv_link) {
            return res.status(400).json({
                success: false,
                message: 'Live TV name and link are required'
            });
        }

        const newLiveTV = new LiveTVModel({
            live_tv_name,
            live_tv_link
        });

        await newLiveTV.save();

        res.status(201).json({
            success: true,
            message: 'Live TV channel added successfully',
            data: newLiveTV
        });

    } catch (error) {
        console.error('Error adding live TV channel:', error);
        res.status(500).json({
            success: false,
            message: 'Error adding live TV channel',
            error: error.message
        });
    }
};

// Get All Live TV Channels
exports.getAllLiveTV = async (req, res) => {
    try {
        const liveTVChannels = await LiveTVModel.find();
        
        // Get recent 20 news articles with selected fields
        const recentNews = await AiNewsModel.find()
            .sort({ _id: -1 })
            .limit(20)
            .select('post_name post_url post_description post_image update_date author_name');

        res.status(200).json({
            success: true,
            data: {
                liveTVChannels,
                recentNews
            }
        });

    } catch (error) {
        console.error('Error fetching live TV channels and news:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching live TV channels and news',
            error: error.message
        });
    }
};

// Update Live TV Channel
exports.updateLiveTV = async (req, res) => {
    try {
        const { id } = req.params;
        const { live_tv_name, live_tv_link } = req.body;

        if (!live_tv_name || !live_tv_link) {
            return res.status(400).json({
                success: false,
                message: 'Live TV name and link are required'
            });
        }

        const updatedLiveTV = await LiveTVModel.findByIdAndUpdate(
            id,
            {
                live_tv_name,
                live_tv_link
            },
            { new: true }
        );

        if (!updatedLiveTV) {
            return res.status(404).json({
                success: false,
                message: 'Live TV channel not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Live TV channel updated successfully',
            data: updatedLiveTV
        });

    } catch (error) {
        console.error('Error updating live TV channel:', error);
        res.status(500).json({
            success: false,
            message: 'Error updating live TV channel',
            error: error.message
        });
    }
};

// Delete Live TV Channel
exports.deleteLiveTV = async (req, res) => {
    try {
        const { id } = req.params;

        const deletedLiveTV = await LiveTVModel.findByIdAndDelete(id);

        if (!deletedLiveTV) {
            return res.status(404).json({
                success: false,
                message: 'Live TV channel not found'
            });
        }

        res.status(200).json({
            success: true,
            message: 'Live TV channel deleted successfully'
        });

    } catch (error) {
        console.error('Error deleting live TV channel:', error);
        res.status(500).json({
            success: false,
            message: 'Error deleting live TV channel',
            error: error.message
        });
    }
};

