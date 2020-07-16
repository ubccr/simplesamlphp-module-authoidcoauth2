<?php

/**
 * Handle linkback() response from IdP.
 */
if (!array_key_exists('state', $_REQUEST) || empty($_REQUEST['state'])) {
    throw new SimpleSAML_Error_BadRequest('Lost state for OIDCOAuth2 endpoint.');
}
$state = SimpleSAML_Auth_State::loadState($_REQUEST['state'], sspmod_authoidcoauth2_Auth_Source_OIDCOAuth2::STAGE_INIT);

// Find authentication source
if (!array_key_exists(sspmod_authoidcoauth2_Auth_Source_OIDCOAuth2::AUTHID, $state)) {
    throw new SimpleSAML_Error_BadRequest('No data in state for ' . sspmod_authoidcoauth2_Auth_Source_OIDCOAuth2::AUTHID);
}
$sourceId = $state[sspmod_authoidcoauth2_Auth_Source_OIDCOAuth2::AUTHID];

$source = SimpleSAML_Auth_Source::getById($sourceId);
if ($source === null) {
    throw new SimpleSAML_Error_BadRequest('Could not find authentication source with id ' . var_export($sourceId, true));
}
try {
    $source->finalStep($state);
} catch (SimpleSAML_Error_Exception $e) {
    SimpleSAML_Auth_State::throwException($state, $e);
} catch (Exception $e) {
    SimpleSAML_Auth_State::throwException($state, new SimpleSAML_Error_AuthSource($sourceId, 'Error on OIDCOAuth2 linkback endpoint.', $e));
}

SimpleSAML_Auth_Source::completeAuth($state);
