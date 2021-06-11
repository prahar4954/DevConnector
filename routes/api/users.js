const express = require('express');
const router = express.Router();

const bcrypt = require('bcryptjs');
const gravatar = require('gravatar');
const jwt = require('jsonwebtoken');
const config = require('config');
const User = require('../../models/User');
const { check, validationResult } = require('express-validator');

// @route POST api/user
// @desc Register user
// @access Public

router.post('/', [
  check('name','Name is required').not().isEmpty(),
  check('email','Please enter valid email').isEmail(),
  check('password','Please enter valid password with >=6 char').isLength({min:6}),
], async (req,res)=> {

  const errors = validationResult(req);
  if(!errors.isEmpty()){
    return res.status(400).json({errors:errors.array()});
  }
  const {email,name,password} = req.body;

  try{
    
    // See if user exists
    let user = await User.findOne({email}); //search user by email
    if(user){
      return res.status(400).json({ errors: [{msg: 'User Already exists'}]});
    }
    
    //get user gravatar
    const avatar = gravatar.url(email,{
      s:'200',  //default size
      r:'pg',   //reading
      d:'mm'    //default image
    })
    user = new User({
      name,
      email,
      avatar,
      password
    });
    
    //encrypt password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password,salt);
    await user.save();
    
    //return jsonwebtoken
    const payload = {
      user:{
        id:user.id
      }
    }
    jwt.sign(
      payload,
      config.get('jwtSecret'),
      {expiresIn: 360000},
      (err,token)=> {
        if(err) throw err;
        res.json({token});
      });
  }catch(err){
    console.log(err.message);
    res.status(500).send('Server error!');
  }
});
module.exports = router;