// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.callout.wssec;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecEncrypt;

import org.w3c.dom.Document;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


public class Encrypt {

    public String encryptMessage(String content, EncryptOptions options) throws Exception {
        Crypto thisCrypto = CryptoFactory.getInstance("crypto.properties");
        return encryptMessage0(content, options, thisCrypto);
    }

    private String encryptMessage0(String content, EncryptOptions options, Crypto crypto) throws Exception {

        Document doc = XmlUtil.toDocument(content);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo(options.alias, options.password);
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setSymmetricEncAlgorithm(WSConstants.AES_256);
        builder.setSymmetricKey(secretKeyConverter(options.secretKey));

        WSEncryptionPart encP =
                new WSEncryptionPart(
                        "add", "http://ws.apache.org/counter/counter_port_type", "Element"
                );
        builder.getParts().add(encP);

        Document encryptedDoc = builder.build(crypto);
        String outputString = XmlUtil.toString(encryptedDoc);
        return outputString;
    }


    public static class EncryptOptions {
        public String alias;
        public String password;
        public String secretKey;
    }

    private SecretKey secretKeyConverter(String secretkey) throws Exception {
        // decode the base64 encoded string
        byte[] decodedKey = Base64.getDecoder().decode(secretkey);
        SecretKey sKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return sKey;
    }
}
