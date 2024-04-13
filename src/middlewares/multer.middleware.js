import multer from "multer";

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, "./public")
    },
    filename: function (req, file, cb) {
      
      cb(null, file.originalname)
      console.log(file)
    }
  })
  
export const upload = multer({ 
    storage, 
})


// import multer from "multer";

// //Define storage for avatar and coverImage
// const storage = multer.diskStorage({
//     destination: function (req, file, cb) {
//         cb(null, "./public/temp")
//     },
//     filename: function (req, file, cb) {
//         cb(null, file.originalname)
//     }
// });

// // Multer configuration for avatar and coverImage
// const upload = multer({ storage: storage });

// export { upload };
