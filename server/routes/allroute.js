const express = require('express');
const axios = require('axios');

const { route } = require('express/lib/application');
const router = express.Router();
const allController = require('../controller/allcontroller');
const adminController = require('../controller/admincontroller');
const sessions = require('express-session');
const uploadNewsImage = require('../middleware/uploadNewsImage');
const uploadDocument = require('../middleware/uploadDocuments');
const uploadImage = require('../middleware/uploadImage');
const appname = "aguli_tv";


// CLIENT SIDE ROUTE//

// API FOR MOBILE APP

//API FOR ADMIN DASHBOARD
router.post('/api/v1/admin/post/news', uploadNewsImage, adminController.AddNewsAdmin);
router.get('/api/v1/admin/newslists', adminController.AdminNewsList);
router.get('/api/v1/admin/authorlist', adminController.authorList);
router.get('/api/v1/admin/imageGallery', adminController.ImageGallery);

router.post('/api/v1/admin/upload/document', (req, res, next) => {
    req.uploadMiddleware = uploadDocument; // Use document middleware
    next();
  }, adminController.uploadDocument);
router.get('/api/v1/admin/get/document', adminController.getDocuments);
router.delete('/api/v1/admin/documents/:id', adminController.deleteDocument);
router.post('/api/v1/admin/upload/image', uploadImage, adminController.uploadImage);


router.get('/api/v1/admin/saasuser/list', adminController.saasUserList);
router.get('/api/v1/admin/pending/content', adminController.getVerifyContent);
router.post('/api/v2/global/user/login', adminController.saasUserAuth);
router.put('/api/v1/admin/:id/approve', adminController.approveNews);
router.get('/api/v1/admin/news/:id', adminController.getSingleNews);
router.put('/api/v1/admin/news/update/:id', uploadNewsImage, adminController.updateNewsById);
router.delete("/api/v1/admin/news/delete/:id", adminController.deleteNewsById);


router.put('/api/v1/admin/author/update/:id', adminController.updateAuthorAI);
router.delete('/api/v1/admin/author/delete/:id', adminController.deleteAuthorAI);



//SAAS USER
router.post('/api/v2/global/user/create', adminController.saasUserCreate);
router.post('/api/v2/global/user/verify', adminController.saasUserVerify);

//AUTHOR LOGIN
router.post('/api/v1/author/login', adminController.authorLogin);
router.get('/api/v1/author/articles', adminController.getAuthorArticles);




//ERROR//






//Aguli TV Route
router.post('/api/v1/'+appname+'/category/add', adminController.addCategory);
router.put('/api/v1/'+appname+'/category/edit/:cat_id', adminController.editCategory);
router.delete('/api/v1/'+appname+'/category/delete/:cat_id', adminController.deleteCategory);
router.get('/api/v1/'+appname+'/category/list', adminController.getCategory);

//Video Route
router.post('/api/v1/'+appname+'/video/add', adminController.createVideo);
router.put('/api/v1/'+appname+'/video/update/:id', adminController.updateVideo);
router.delete('/api/v1/'+appname+'/video/delete/:id', adminController.deleteVideo);
router.get('/api/v1/'+appname+'/video/getallvideos', adminController.getAllVideos);
router.get('/api/v1/'+appname+'/video/getvideomobile', adminController.getVideoMobile);
router.get('/api/v1/'+appname+'/video/getvideo/:id', adminController.getVideoById);
router.get('/api/v1/'+appname+'/video/getvideocategories', adminController.getVideoCategories);

//Profile Route
router.post('/api/v1/'+appname+'/profile/google/signin', adminController.googleSignIn);
router.get('/api/v1/'+appname+'/profile/get/:googleId', adminController.getProfile);
router.put('/api/v1/'+appname+'/profile/update/:googleId', adminController.updateProfile);
router.post('/api/v1/'+appname+'/profile/upload/:googleId', adminController.uploadProfilePicture);

//Explore Route
router.post('/api/v1/'+appname+'/explore/add', adminController.createExplore);
router.get('/api/v1/'+appname+'/explore/getall', adminController.getAllExplore);
router.delete('/api/v1/'+appname+'/explore/delete/:id', adminController.deleteExplore);
router.put('/api/v1/'+appname+'/explore/like/:id', adminController.toggleLike);


//API FOR MOBILE APP NEWS
router.get('/api/v1/mobile/category', adminController.getCategoryMobile);
router.get('/api/v1/mobile/news', allController.getNewsByCategory);
router.get('/api/v1/mobile/getnewsbyid', allController.getNewsbyId);

//API FOR PUSH NOTIFICATIONS
router.post('/api/v1/push/notification', adminController.sendPushNotification);

//API FOR LIVE TV
router.post('/api/v1/'+appname+'/livetv/add', adminController.addLiveTV);
router.get('/api/v1/'+appname+'/livetv/getall', adminController.getAllLiveTV);
router.put('/api/v1/'+appname+'/livetv/update/:id', adminController.updateLiveTV);
router.delete('/api/v1/'+appname+'/livetv/delete/:id', adminController.deleteLiveTV);


//API FOR CITIZEN
router.post('/api/v1/'+appname+'/citizen/add', adminController.addCitizen);
router.get('/api/v1/'+appname+'/citizen/getall', adminController.getCitizens);
router.delete('/api/v1/'+appname+'/citizen/delete/:id', adminController.deleteCitizen);






module.exports = router;
