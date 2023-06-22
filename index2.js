var express = require('express');
var app = express();
var path = require('path');
var bodyParser = require('body-parser');
var fs = require('fs');
var url = require('url');
var axios = require('axios');
var crypto = require('crypto');

const jwt = require("jsonwebtoken");

const characters ='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const state = characters.charAt(Math.floor(Math.random() * 32));
const nonce = characters.charAt(Math.floor(Math.random() * 32));

var pkceChallenge = (length) => {
    let codeVerifier = '';
    const charactersLength = characters.length;
    for ( let i = 0; i < length; i++ ) {
        codeVerifier += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    const getChallenge = (codeVerifier) => {
        return crypto.createHash('sha256')
            .update(codeVerifier)
            .digest('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '')
    }
    // console.log("Code Challenge: "+getChallenge(codeVerifier))
    // console.log("Code Verifier: "+codeVerifier)
    return {
        "codeChallenge":getChallenge(codeVerifier),
        "codeVerifier":codeVerifier
    }
}
const pkce = pkceChallenge(43);
console.log(pkce);

// console.log(pkceChallenge(43))
app.engine('html', require('ejs').renderFile);

// create application/json parser
var jsonParser = bodyParser.json();
// create application/x-www-form-urlencoded parser
var urlencodedParser = bodyParser.urlencoded({ extended: false });

app.post('/saveConfigure', jsonParser, (req, res) => {
    console.log('printing req body');
    console.log(req.body);
    let oauthDetails = req.body;
    fs.writeFile('idpConfig.json', JSON.stringify(oauthDetails), ()=>{
        console.log('IDP Configuration save to idpConfig.json file.');
    });
    res.status(200).send('All form submitted');
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname + '/html_files/welcome.html'));
});


app.get('/authCode', (req, res) => {
    fs.readFile('./idpConfig.json', (err, data) => {
        if(!err){
            //
            let idpData = JSON.parse(data);
            res.redirect(url.format({
                pathname: idpData.authEndpoint,
                query: {
                    'client_id': idpData.client_id,
                    'response_type': 'code',
                    'response_mode': 'query',
                    'scope': 'openid profile',
                    'redirect_uri': 'http://localhost:8080/authCodeValidator',
                    'state': state,
                    'nonce': nonce,
                    "code_challenge_method":"S256",
                    "code_challenge": pkce.codeChallenge
                }
            }))
        }else{
            res.status(400).send('Bad Request: '+err);
        }
    });
});

app.get('/authCodeValidator', (req, res) => {
    let code = req.query.code;
    let state = req.query.state;
    // || url.parse(req.protocol+'://'+req.hostname+''+req.originalUrl,true, true)
    //console.log(state);
    if(state===state){
        if(code!==null||code!==''){
            fs.readFile('./idpConfig.json', (err, data) => {
                if(!err){
                    let idpData = JSON.parse(data);
                    let client_id = idpData.client_id;
                    // let client_Secret = idpData.client_secret;
                    // let clientCredentials = new Buffer(''+client_id+':'+client_Secret);
                    // let base64ClientCredentials = clientCredentials.toString('base64');
                    let headers = {
                        // 'Authorization': 'Basic '+base64ClientCredentials,
                        'Accept': 'application/json',
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Connection': 'close',
                        'Content-Length': '0'
                    };
                    // axios.post(idpData.tokenEndpoint, {
                        // grant_type: 'authorization_code',
                        // redirect_uri: 'http://localhost:8080/showTokens',
                        // code: code
                    // },headers)
                    axios({
                        method: 'post',
                        url: idpData.tokenEndpoint,
                        params: {
                            'grant_type': 'authorization_code',
                            'redirect_uri': 'http://localhost:8080/authCodeValidator',
                            'code': code,
                            'client_id':client_id,
                            "code_verifier": pkce.codeVerifier

                        },
                        headers:{
                            // 'Authorization': 'Basic '+base64ClientCredentials,
                            'Accept': 'application/json',
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Connection': 'close',
                            'Content-Length': '0' 
                        }
                    })
                    .then((resAxios) => {
                        console.log(resAxios);
                        const decoded = jwt.decode(resAxios.data.id_token);
                        // res.status(200).send(decoded);
                        res.render(__dirname+"/html_files/decoded.html", {decoded:decoded})
                    })
                    .catch(err => {
                        console.log(err);
                        res.status(400).send('Bad Request: '+err);
                    });
                }else{
                    res.status(400).send('Bad Request: '+err);
                }
            });
        }else{
            res.status(400).send("Invalid Code returned from IDP: "+state);  
        }
    }else{

        res.status(400).send("Invalid State: "+state);
    }
});

app.get('/implicit', (req, res) => {
    fs.readFile('./idpConfig.json', (err, data) => {
        if(!err){
            let idpData = JSON.parse(data);
            res.redirect(url.format({
                pathname: idpData.authEndpoint,
                query: {
                    'client_id': idpData.client_id,
                    'response_type': 'token',
                    'scope': 'openid profile',
                    'redirect_uri': 'http://localhost:8080/authCodeValidator',
                    'state': "logged_in",
                    'nonce': "somerandomstring"
                }
            }))
        }else{
            res.status(400).send('Bad Request: '+err);
        }
    });
});

app.get('/clientCredentials', (req, res) => {
    fs.readFile('./idpConfig.json', (err, data) => {
        if(!err){
            let idpData = JSON.parse(data);
            let client_id = idpData.client_id;
            let client_Secret = idpData.client_secret;
            let clientCredentials = new Buffer(''+client_id+':'+client_Secret);
            let base64ClientCredentials = clientCredentials.toString('base64');
            axios({
                method: 'post',
                url: idpData.tokenEndpoint,
                params: {
                    'grant_type': 'client_credentials',
                    'scope': 'custom_scope_1',
                },
                headers:{
                    'Authorization': 'Basic '+base64ClientCredentials,
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'cache-control': 'no-cache'
                }
            })
            .then((resAxios) => {
                console.log(resAxios);
                res.status(200).send(resAxios.data);
            })
            .catch(err => {
                console.log(err);
                res.status(400).send('Bad Request: '+err);
            });
        }else{
            res.status(400).send('Bad Request: '+err);
        }
    });
});




app.listen(process.env.PORT || 8080, ()=> {
    console.log('Server is up and listening on port 8080');
});