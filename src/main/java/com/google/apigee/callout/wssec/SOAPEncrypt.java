// Copyright 2018 Google Inc.
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

import com.apigee.flow.execution.spi.Execution;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.Message;
import com.apigee.flow.message.MessageContext;
import java.util.Map;
import org.apache.commons.lang3.exception.ExceptionUtils;

public class SOAPEncrypt extends WsSecCalloutBase implements Execution {
    public SOAPEncrypt(Map properties) {
        super(properties);
    }

    private boolean getIncludeSignatureToken(MessageContext msgCtxt) throws Exception {
        String dest = getSimpleOptionalProperty("include-signature-token", msgCtxt);
        boolean inc = (dest != null) && Boolean.parseBoolean(dest);
        return inc;
    }

    @Override
    public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext execCtxt) {

        try {
            Message msg = msgCtxt.getMessage();
            String msgContent = msg.getContent();
            Encrypt encrypter = new Encrypt();

            Encrypt.EncryptOptions options = new Encrypt.EncryptOptions();
            options.alias = getSimpleRequiredProperty("alias", msgCtxt);
            options.password = getSimpleRequiredProperty("password", msgCtxt);
            options.secretKey = getSimpleRequiredProperty("secretKey", msgCtxt);

            String encryptedMessage = encrypter.encryptMessage(msgContent, options);
            String outputVar = getOutputVar(msgCtxt);
            msgCtxt.setVariable(outputVar, encryptedMessage);
        }
        catch (Exception e) {
            if (getDebug()) {
                System.out.println(ExceptionUtils.getStackTrace(e));
            }
            String error = e.toString();
            msgCtxt.setVariable(varName("exception"), error);
            int ch = error.lastIndexOf(':');
            if (ch >= 0) {
                msgCtxt.setVariable(varName("error"), error.substring(ch+2).trim());
            }
            else {
                msgCtxt.setVariable(varName("error"), error);
            }
            msgCtxt.setVariable(varName("stacktrace"), ExceptionUtils.getStackTrace(e));
            return ExecutionResult.ABORT;
        }

        return ExecutionResult.SUCCESS;
    }

}

