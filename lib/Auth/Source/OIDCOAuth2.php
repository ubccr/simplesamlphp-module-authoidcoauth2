<?php

require_once dirname(dirname(dirname(dirname(dirname(__FILE__))))) . '/oauth/lib/Consumer.php';
require_once dirname(dirname(dirname(dirname(dirname(__FILE__))))) . '/oauth/libextinc/OAuth.php';

/**
 * Authenticate with OIDC via OAuth2
 *
 * @package SimpleSAMLphp
 */
class sspmod_authoidcoauth2_Auth_Source_OIDCOAuth2 extends SimpleSAML_Auth_Source
{
    /**
     * The string used to identify our states.
    */
    const STAGE_INIT = 'oidcoauth2:init';

    /**
     * The key of the AuthId field in the state.
    */
    const AUTHID = 'oidcoauth2:AuthId';

    private $authEndpoint;
    private $apiEndpoint;
    private $key;
    private $secret;
    private $scope;
    private $reponseType;
    private $redirectUri;
    private $curl;
    private $verifySSL;
    private $isAuthInHeadder;

    /**
     * Constructor for this authentication source.
     *
     * @param array $info   Information about this authentication source.
     * @param array $config Configuration.
     */
    public function __construct($info, $config)
    {
        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);
        $this->apiEndpoint = $config['api_endpoint'];
        $this->authEndpoint = array_key_exists('auth_endpoint', $config) ? $config['auth_endpoint'] : $config['api_endpoint'];
        $this->key = $config['key'];
        $this->secret = $config['secret'];
        $this->scope = $config['scope'];
        $this->responseType = $config['response_type'];
        $this->redirectUri= $config['redirect_uri'];
        $this->verifySSL = array_key_exists('verify_ssl', $config) ? $config['verify_ssl'] : 2;
        $this->isAuthInHeader = array_key_exists('use_header_for_auth', $config) ? $config['use_header_for_auth'] : true;
        $this->curl = curl_init();
        curl_setopt($this->curl, CURLOPT_USERAGENT, 'SSPHP OIDC/OAuth2');
        curl_setopt($this->curl, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($this->curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($this->curl, CURLOPT_SSL_VERIFYHOST, $this->verifySSL);
        curl_setopt($this->curl, CURLOPT_SSL_VERIFYPEER, 2);
        curl_setopt($this->curl, CURLINFO_HEADER_OUT, true);
    }

    /**
     * Wrapper for Curl Requests
     *
     * @param string path
     * @param boolean signed
     * @param string token
     * @param string qs
     * @param array contents
     * @param string method
     *
     * @return The response from the endpoint where we made the request.
     */
    protected function doCurlRequest(
        $path,
        $useHeaderForAuth = true,
        $token = null,
        $qs = null,
        $contents = null,
        $method = 'GET'
    ) {

        if ($useHeaderForAuth) {
            curl_setopt($this->curl, CURLOPT_USERPWD, $this->key . ":" . $this->secret);
        } else {
            curl_setopt($this->curl, CURLOPT_USERPWD, null);
        }

        $endPoint = $this->apiEndpoint . $path . (($qs !== null) ? $qs : '');
        curl_setopt($this->curl, CURLOPT_URL, $endPoint);

        if ($method === 'POST') {
            curl_setopt($this->curl, CURLOPT_POSTFIELDS, OauthUtil::build_http_query($contents));
        } else { // do GET by default
            $header = 'Authorization: Bearer ' . $token;
            curl_setopt($this->curl, CURLOPT_HTTPHEADER, array($header));
            curl_setopt($this->curl, CURLOPT_HTTPGET, true);
        }
        $result = curl_exec($this->curl);
        $outInfo = curl_getinfo($this->curl);

        if (!$result) {
            throw new SimpleSAML_Error_Error(curl_error($this->curl));
        }
        if ($result && $outInfo['http_code'] === 200) {
            // return GETs as associative array, we want user info to be easily dumped into SAML attributes.
            return json_decode($result, $method !== 'POST');
        } else {
            switch($outInfo['http_code']) {
                case 400:
                    throw new SimpleSAML_Error_BadRequest($outInfo['http_code'] . ': Could not retrieve data from service.' . print_r($outInfo, true));
                    break;
                case 403:
                    throw new SimpleSAML_Error_InvalidCredential($outInfo['http_code'] . ': Invalid credentials specified.' . print_r($outInfo, true));
                    break;
                case 404:
                    throw new SimpleSAML_Error_NotFound($outInfo['http_code'] . ': Resource not found.' . print_r($outInfo, true));
                    break;
                default:
                    throw new SimpleSAML_Error_Error($outInfo['http_code'] . ': An unknown error occured.' . print_r($outInfo, true));
                    break;
            }
        }
    }

    /**
     * Obtain an Authorization Code
     *
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(&$state)
    {
        // We are going to need the authId in order to retrieve this authentication source later
        $state[self::AUTHID] = $this->authId;

        $stateID = SimpleSAML_Auth_State::getStateId($state);
        $request = array(
            'client_id' => $this->key,
            'scope' =>  $this->scope,
            'state' => $stateID,
            'response_type' => 'code',
            'redirect_uri' => $this->redirectUri
        );
        $state['oidcoauth2:request'] = $request;
        $urlAppend = \SimpleSAML\Utils\HTTP::addURLParameters($this->authEndpoint . '/auth', $request);
        SimpleSAML_Auth_State::saveState($state, self::STAGE_INIT);
        $consumer = new sspmod_oauth_Consumer($this->key, $this->secret);
        $authorizeUrl = $consumer->getAuthorizeRequest($urlAppend, $request);
    }

    /**
     * Exchange authorization code for an access token
     *
     * @param array &$state Information about the current authentication.
     */
    public function finalStep(&$state)
    {
        $request = array(
            'code' => $_GET['code'],
            'redirect_uri' => $this->redirectUri,
            'grant_type' => 'authorization_code'
        );
        if (!$this->isAuthInHeader) {
            $request['client_id'] = $this->key;
            $request['client_secret'] = $this->secret;
        }
        // Exchange the code we got earlier for an access token
        $result = $this->doCurlRequest('/token', $this->isAuthInHeader, null, null, $request, 'POST');
        // Use this access token to tell us about our current user + affiliations
        $userInfo = $this->doCurlRequest('/userinfo', $this->isAuthInHeader, $result->access_token);
        foreach($userInfo as $key => $value){
            $state['Attributes'][$key] = array($value);
        }
    }
}
