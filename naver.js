const lzstring = require("./lz-string");

module.exports = (function () {
	function naver(email, password) {
		this.email = email;
		this.password = password;
		this.userAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101 Firefox/64.0";
		this.uuid = java.util.UUID.randomUUID().toString();
	}
	
	function byteToHex(byte) {
		const sb = new java.lang.StringBuffer();
		for (let i in byte) sb.append(java.lang.Integer.toString((byte[i]&0xff) + 0x100, 16).substring(1));
		return sb.toString();
	}
	
	function rsaEncrypt(nValue, eValue, text) {
		const keyFactory = java.security.KeyFactory.getInstance("RSA");
		const pubKeySpec = new java.security.spec.RSAPublicKeySpec(new java.math.BigInteger(nValue, 16), new java.math.BigInteger(eValue, 16));
		const key = keyFactory.generatePublic(pubKeySpec);
		const cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key); 
		const byte = cipher.doFinal(new java.lang.String(text).getBytes("UTF-8"));
		return byteToHex(byte);
	}
	
	function getLenChar(value) { 
		return String.fromCharCode(value.length);
	}

	naver.prototype.login = function () {
		const res = org.jsoup.Jsoup.connect("https://nid.naver.com/login/ext/keys.nhn").get().text();
		
		const sessionKey = res.split(",")[0];
		const keyName = res.split(",")[1];
		const nValue = res.split(",")[2];
		const eValue = res.split(",")[3];
		
		const message = getLenChar(sessionKey) + sessionKey + getLenChar(this.email) + this.email + getLenChar(this.password) + this.password;
		const text = rsaEncrypt(nValue, eValue, message);
		
		const json = {
			"a": this.uuid + "-4",
			"b": "1.3.4",
			"c": true,
			"d": [{
				"i": "id",
				"a": [],
				"b": {
					"a": ["0, " + this.email],
					"b": 0
				},
				"c": "",
				"d": this.email,
				"e": false,
				"f": false
			}, {
				"i": "pw",
				"e": true,
				"f": false
			}],
			"h": "1f",
			"i": {
				"a": this.userAgent
			}
		};
		
		const encData = lzstring.compressToEncodedURIComponent(JSON.stringify(json));
		const bvsd = {
			"uuid": this.uuid,
			"encData": encData
		};
		
		const connection = org.jsoup.Jsoup.connect("https://nid.naver.com/nidlogin.login");
		connection.header("Referer", "https://nid.naver.com/nidlogin.login");
		connection.header("Content-Type", "application/x-www-form-urlencoded");
		connection.header("User-Agent", this.userAgent);
		connection.requestBody("localechange=&encpw=" + text + "&enctp=1&svctype=1&smart_LEVEL=-1&bvsd=" + bvsd + "&encnm=" + keyName + "&locale=ko_KR&url=https://www.naver.com&id=&pw=");
		connection.method(org.jsoup.Connection.Method.POST);
		
		const response = connection.execute();
		
		if (response.statusCode() == 302)
		this.cookies = response.cookies();
		else throw new Error("로그인에 실패했습니다. 원인은 캡챠 혹은 이메일, 비밀번호가 잘못된거 같습니다.");
		
		return true;
	}
	
	return naver;
})();