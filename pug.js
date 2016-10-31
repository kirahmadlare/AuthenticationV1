const pug = require('pug');
pug.render('block content
  form(method='POST')
    legend Login
    .form-group
      label(for='username') Username
      input.form-control(type='text', name='username', autofocus)
    .form-group
      label(for='password') Password
      input.form-control(type='password', name='password')
    button.btn.btn-primary(type='submit') Login
    a.btn.btn-link(href='/forgot') Forgot Password?');

