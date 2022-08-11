library telebirr;

import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:http/http.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:sortedmap/sortedmap.dart';
import 'package:http/http.dart' as http;

class Telebirr {
  String baseURL = "http://196.188.120.3:10443/service-openup/toTradeWebPay";
  String appID; // your app id assigned by ethiotelecom
  String appKey; // your app key assigned by ethiotelecom
  String publicKey;
  String notifyURL;
  String receiverName;
  String returnURL;
  String shortCode;
  String subject;
  String timeoutExpress;
  String totalAmount;
  String nonce;
  String outTradeNo;
  late Map<String, String> credentials;
  Telebirr(
      this.appID,
      this.appKey,
      this.publicKey,
      this.notifyURL,
      this.receiverName,
      this.returnURL,
      this.shortCode,
      this.subject,
      this.timeoutExpress,
      this.totalAmount,
      this.nonce,
      this.outTradeNo) {
    String timeStamp = DateTime.now().millisecondsSinceEpoch.toString();
    credentials = {
      "appId": appID,
      "notifyUrl": notifyURL,
      "outTradeNo": outTradeNo,
      "receiveName": receiverName,
      "returnUrl": returnURL,
      "shortCode": shortCode,
      "subject": subject,
      "timeOutExpress": timeoutExpress,
      "totalAmount": totalAmount,
      "nonce": nonce,
      "timestamp": timeStamp,
    };
  }

  String _encrypt(String publicKey, Map<String, String> message) {
    final rsaPublicKey = RSAKeyParser().parse(publicKey) as RSAPublicKey;
    final encrypter =
        Encrypter(RSA(publicKey: rsaPublicKey, encoding: RSAEncoding.PKCS1));
    final iv = IV.fromLength(117);
    final encryptedPublicKey = encrypter.encrypt(json.encode(message), iv: iv);
    return encryptedPublicKey.base64;
  }

  String _sign(Map<String, String> credentials, String appKey) {
    credentials['appKey'] = appKey;
    var orderedCredentials = SortedMap(const Ordering.byKey());
    orderedCredentials.addAll(credentials);
    String formatedCredential = _formatCredential(orderedCredentials);
    String hashedCredential = _hashCredentials(formatedCredential);
    return hashedCredential;
  }

  String _formatCredential(SortedMap credentials) {
    var formatedString = "";
    credentials.forEach((key, value) {
      if (formatedString == "") {
        formatedString = "$key=$value";
      } else {
        formatedString += "&$key=$value";
      }
    });
    return formatedString;
  }

  String _hashCredentials(String credentials) {
    var credBytes = utf8.encode(credentials);
    var hashedCredentials = sha256.convert(credBytes).toString();
    return hashedCredentials;
  }

  Future<Response> sendRequest() {
    String encryptedCredentials = _encrypt(publicKey, credentials);
    String signature = _sign(credentials, appKey);
    var requestParams = {
      "appid": appID,
      "sign": signature,
      "ussd": encryptedCredentials
    };
    var url = Uri.parse(baseURL);
    return http.post(url, body: json.encode(requestParams));
  }
}
