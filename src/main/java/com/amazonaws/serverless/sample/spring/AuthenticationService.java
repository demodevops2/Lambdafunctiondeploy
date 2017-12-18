package com.amazonaws.serverless.sample.spring;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentity;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentityClient;
import com.amazonaws.services.cognitoidentity.model.GetIdRequest;
import com.amazonaws.services.cognitoidentity.model.GetIdResult;
import com.amazonaws.services.cognitoidentity.model.GetOpenIdTokenRequest;
import com.amazonaws.services.cognitoidentity.model.GetOpenIdTokenResult;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClient;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.ChallengeNameType;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithWebIdentityResult;
import com.fasterxml.jackson.databind.ObjectMapper;

public class AuthenticationService {
	
	/**
	 * Logger
	 */
	Logger logger = LoggerFactory.getLogger(AuthenticationService.class);
	
	static AmazonDynamoDB client = AmazonDynamoDBClientBuilder.standard().build();
    static DynamoDB dynamoDB = new DynamoDB(client);
    
	/**
	 * getOpenIDToken()
	 * @param restUrl service url
	 * @param method rest method
	 * @param requestBody input body
	 * @return response
	 */
	private String getOpenIDToken(String restUrl, String method,Map<String, String> parameters) {
		String client_id = "48te0qlervfpp6t0lg4n3m7ugb";
		String redirect_uri = "https://localhost:8443/HelloWorldJSP/callback.html";
		restUrl = "https://hsbcuser.auth.ap-southeast-2.amazoncognito.com/oauth2/authorize?&response_type=token&client_id="+client_id+"&redirect_uri="+redirect_uri+"&state=STATE&scope=aws.cognito.signin.user.admin";
		StringBuilder response = new StringBuilder();
		BufferedReader br = null;
		logger.info("callToRestService start ");
		logger.info("restUrl  : " + restUrl);
		try {
			URL url = new URL(restUrl);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
			conn.setDoOutput(true);
			conn.setRequestMethod(method);
			conn.setRequestProperty("Content-Type", "application/json");
			conn.setRequestProperty("Accept", "application/json");

			ObjectMapper objectMapper = new ObjectMapper();
			String requestParams = objectMapper.writeValueAsString(parameters);
			logger.info("requestParams : " + requestParams);
			if (parameters.get("otp") != null) {
				OutputStream os = conn.getOutputStream();
				os.write(requestParams.getBytes(Charset.forName("UTF-8")));
				os.flush();
			}

			if (conn.getResponseCode() != 200) {
				throw new RuntimeException("Failed : HTTP error code : " + conn.getResponseCode());
			}
			br = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));

			String output;
			logger.info("Output from Server .... \n");
			while ((output = br.readLine()) != null) {
				response.append(output);
			}
			logger.info("response : " + response.toString());
			// br.close();
			conn.disconnect();
		} catch (MalformedURLException e) {
			logger.error("MalformedURLException : " + e.getMessage());
			e.printStackTrace();
		} catch (IOException e) {
			logger.error("IOException : " + e.getMessage());
			e.printStackTrace();
		} finally {
			try {
				if (br != null) {
					br.close();
				}
			} catch (IOException e) {
				logger.error("IOException : " + e.getMessage());
			}
		}
		System.out.println("Responce ******** " + response.toString());
		return response.toString();
	}
	
	
	private static String getIDAndToken(){
		try {
			
			// Get ID
			
			AmazonCognitoIdentity identityClient  = new AmazonCognitoIdentityClient(new AnonymousAWSCredentials());
			GetIdRequest idRequest =  new GetIdRequest();
			idRequest.setAccountId("967958050410");
			idRequest.setIdentityPoolId("ap-southeast-2:32a85510-63a4-456d-beb5-09f42aa45181");
			GetIdResult idResult =  identityClient.getId(idRequest);
			String identityId = idResult.getIdentityId();
			
			System.out.println("identityId ..." + identityId);
			
			// Get Token
			GetOpenIdTokenRequest tokenRequest =  new GetOpenIdTokenRequest();
			tokenRequest.setIdentityId(identityId);
			
			GetOpenIdTokenResult tokenResp =  identityClient.getOpenIdToken(tokenRequest);
			// get the OpenID token from the response
			String openIdToken = tokenResp.getToken();
			
			System.out.println("openIdToken ..." + openIdToken);
			
			// you can now create a set of temporary, limited-privilege credentials to access
			// your AWS resources through the Security Token Service utilizing the OpenID
			// token returned by the previous API call. The IAM Role ARN passed to this call
			// will be applied to the temporary credentials returned
			
			AWSSecurityTokenService stsClient = new AWSSecurityTokenServiceClient(new AnonymousAWSCredentials());
			
			AssumeRoleWithWebIdentityRequest stsReq = new AssumeRoleWithWebIdentityRequest();
			stsReq.setRoleArn("arn:aws:iam::967958050410:role/Cognito_HSBCIdentityPoolAuth_Role");
			stsReq.setWebIdentityToken(openIdToken);
			stsReq.setRoleSessionName("AppTestSession");
						
			AssumeRoleWithWebIdentityResult stsResp = stsClient.assumeRoleWithWebIdentity(stsReq);
			com.amazonaws.services.securitytoken.model.Credentials stsCredentials = stsResp.getCredentials();

			// Create the session credentials object
			AWSSessionCredentials sessionCredentials = new BasicSessionCredentials(
				stsCredentials.getAccessKeyId(),
				stsCredentials.getSecretAccessKey(),
				stsCredentials.getSessionToken()
			);
			
			

			retrieveItem();
		} catch (Exception e){
			
		}
		
		return "";
	}
	
	
	private static void retrieveItem() {
        Table table = dynamoDB.getTable("ProductCatalog");

        try {

            Item item = table.getItem("Id", "100");

            System.out.println("Printing item after retrieving it....");
            System.out.println(item.toJSONPretty());

        }
        catch (Exception e) {
            System.err.println("GetItem failed.");
            System.err.println(e.getMessage());
        }

    }
	
	/*public static void main(String ... strings) {
		//AuthenticationService.getIDAndToken();
		AuthenticationService.testAuth();
	}*/
	
	
	public static void testAuth() {
		Map<String, String> authParams = new HashMap<String, String>();
		authParams.put("USERNAME", "arul");
		authParams.put("PASSWORD", "Aws@1234");
		AWSCognitoIdentityProviderClient cognitoClient = new AWSCognitoIdentityProviderClient();
		AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest()
		        .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
		        .withAuthParameters(authParams)
		        .withClientId("55vtqakpr8r9acf4fp08ju6466")
		        .withUserPoolId("us-west-2:4ef84041-6876-47ef-8554-0a5e9bb6e3ac");

		AdminInitiateAuthResult authResponse = cognitoClient.adminInitiateAuth(authRequest);
		if (authResponse.getChallengeName().equals(""))
		{
		    System.out.println("Responce :" + authResponse.getAuthenticationResult());
		    return;
		}
		else if (ChallengeNameType.NEW_PASSWORD_REQUIRED.name().equals(authResponse.getChallengeName()))
		{
			System.out.println("{} attempted to sign in with temporary password");
		    
		}
		else
		{
		    throw new RuntimeException("unexpected challenge on signin: " + authResponse.getChallengeName());
		}
	}
}
