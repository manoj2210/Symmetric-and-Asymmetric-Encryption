var CryptoJS = require("crypto-js");
var JSEncrypt=require("node-jsencrypt");

//chars - characters to pick from
var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz*&-%/!?*+=()";

// Generates a ramdom key of Specified Length
var generateKey = function generateKey(keyLength){
  var randomstring = '';
  
  for (var i=0; i < keyLength; i++) {
    var rnum = Math.floor(Math.random() * chars.length);
    randomstring += chars.substring(rnum,rnum+1);
  }
  return randomstring;
};
// encrypt a javascript object into a payload to be sent
// to a server or stored on the client
var publicKey = "-----BEGIN PUBLIC KEY-----MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA4BrwgnKbOjcN/ABthBSq1CuMuE7v59HvyZnQSJJWSkQcHtFLt2RB2Di2T0nbxbMA5A+8GxVeZL8HcU3xvj9TiAw28mu1ZLxx5GzrjmHuzk4DKsrL88IJR1K7G4nBSAQLHNyMGDzDGGMWcyNumygfT7OeR+RhMeFEZdXPfcDqrOf8bbb1uYjvzKFIKealsxccPJ+ShfCobKJhH9cwq/5M3KYYaZSimbvVjJ0QffbP9YlZOqnBTTCZ6koBLOSwNGPM0FVuhjzOrD5Tb85GGtS8gG2OjCxcBnPQkg3VM5CemJSFgxX2+cFrOOeRpm2Y0Nhxy8iiJzTyZCaHckxyPEGnQbv2yGXMj3IlFbRjh5ErWGpL3dvgx0i2ktn64WKpOfUsEh5fi4tAW0u0l6eL/A+owDJXjpOrhyc7S1niZ+lijzUefObObUh/zkLcyrTuMlzVT1mTz59ESobmhcHS6+RLLiprxfvmamzxoVpXvDBI4RexTA0kwhpGDsp36OYePUeRW3WAv5ikDbn6/IlvE2NqDabehzu8vyCKagM75W3s5J6Fy9uklKjl+EgRAbTKXwLIxtssOeN0n6ko8kodGSsmXp0DFZf9TZCWRhz/fNduKwMHQkXsERD/LwHrDT2kGBGArhqJzx9mkNqmZuv26prfhmTKg22Wun/DcHkS/1eiZ3sCAwEAAQ==-----END PUBLIC KEY-----";

var encrypt = function encrypt(data, publicKey) {
  // Create a new encryption key (with a specified length)
  var key = generateKey(50);
  // convert data to a json string
  var dataAsString = JSON.stringify(data);
  // encrypt the data symmetrically 
  // (the cryptojs library will generate its own 256bit key!!)
  var aesEncrypted = CryptoJS.AES.encrypt(dataAsString, key);
  // get the symmetric key and initialization vector from
  // (hex encoded) and concatenate them into one string
  var aesKey = aesEncrypted.key + ":::" + aesEncrypted.iv;
  // the data is base64 encoded 
  var encryptedMessage = aesEncrypted.toString();

  // we create a new JSEncrypt object for rsa encryption
  var rsaEncrypt = new JSEncrypt();
  
  // we set the public key (which we passed into the function)
  rsaEncrypt.setPublicKey(publicKey);
  // now we encrypt the key & iv with our public key
  var encryptedKey = rsaEncrypt.encrypt(aesKey);
  // and concatenate our payload message
  var payload = encryptedKey + ":::" + encryptedMessage;
  console.log(payload);
};

encrypt("{'Name':'Manoj'}",publicKey);