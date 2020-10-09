var express = require('express');
var router = express.Router();

router.get('/member_only', (req, res) => {
  res.render('member_only', {title: 'Member only page', user: req.user});
});

module.exports = router;