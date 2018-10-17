var mongoose = require('mongoose');

// console.log(process.env);

mongoose.connect(process.env.MONGOOSE_URI);