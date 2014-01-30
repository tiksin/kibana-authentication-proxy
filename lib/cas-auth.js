/**
 * Configure CAS Authentication
 * When no cas_server_url presented, no CAS authentication applied.
 */


exports.configureCas = function(express, app, config) {

  if (!config.enable_cas_auth) {
    console.log('Warning: No CAS authentication presented');
    return;
  } else {
    console.log('Info: CAS Authentication applied');
  }

  app.use(function(req, res, next) {
    if (req.url.indexOf('/auth/cas/login') === 0 || req.session.cas_user_name) {
      return next();
    } else {
      res.redirect('/auth/cas/login');
    }
  });

  config.cas_server_url = config.cas_server_url.replace(/\s+$/,'');

  app.get('/auth/cas/login', function (req, res) {
    var CAS = require('cas-client-edqm');
    var cas = new CAS({base_url: config.cas_server_url,
                       service: config.cas_service_url,
                       version: config.cas_protocol_version
                  });

    var cas_login_url = config.cas_server_url + "/login?service=" + config.cas_service_url;

    var ticket = req.param('ticket');
    if (ticket) {
      cas.validate(ticket, function(err, status, username, extended) {
        if (err || !status) {
          // Handle the error
          res.send(
            "You may have logged in with invalid CAS ticket or permission denied.<br>" +
              "<a href='" + cas_login_url + "'>Try again</a>"
          );
        } else {
          // Log the user in
          req.session.cas_user_name = username;
          var groups = extended['attributes']['cas:' + config.cas_attributes][0];
          var regex = new RegExp(config.auth_group);
          var match = regex.exec(groups);
          if (!match)
             { res.send("Access Forbidden !!"); }
          else { res.redirect("/");}
        }
      });
    } else {
      if (!req.session.cas_user_name) {
        res.redirect(cas_login_url);
      } else {
        res.redirect("/");
      }
    }

  });
};
