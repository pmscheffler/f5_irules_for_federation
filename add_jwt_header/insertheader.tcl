when RULE_INIT priority 100 {

    # if set to 0, log items will appear in /var/log/ltm
    # view from bash with tail -f /var/log/ltm
    set static::debug 1
}

when ACCESS_POLICY_AGENT_EVENT priority 100 {

    # grab the id of the event
    set pspid [ACCESS::policy agent_id]
    if { $static::debug } {log local0. "PSP iRuleID $pspid"}

    # are we in the correct event, it needs to match the iRule event in the Per Session Policy
    if { $pspid eq "psp_add_jwt" } {

        # get the current JWT and store it in our own variable
        # the JWT is stored securely
        ACCESS::session data set -secure "session.custom.userdata.jwt" [ACCESS::session data get -secure "session.oauth.client.last.id_token"]
        set path [HTTP::path]

        if { $static::debug } {log local0. "Adding [string range [ACCESS::session data ge -secure "session.custom.userdata.jwt"] 0 15] on $path"}
    }

}

when ACCESS_PER_REQUEST_AGENT_EVENT priority 100 {

    # get the id of the iRule event from the Per Request Policy
    set prpid [ACCESS::perflow get perflow.irule_agent_id]

    if { $static::debug } {log local0. "PRP iRuleID $prpid"}

    if { $prpid eq "prp_add_jwt" } {

        # This is only used for logging
        if { $static::debug } {set path [HTTP::path]}
        
        set userdatajwt [ACCESS::session data get -secure "session.custom.userdata.jwt"]
        HTTP::header insert "Authorization" "Bearer $userdatajwt"
        if { $static::debug } {log local0. "Adding JWT ([string range [ACCESS::session data get -secure "session.custom.userdata.jwt"] 0 15]) to Authorization header on $path"}
    }
}

when HTTP_REQUEST_RELEASE priority 100 {

    # for debugging purposes only
    if { $static::debug }{
        foreach aHeader [HTTP::header names] {
            log local0. "HTTP Request Headers: $aHeader: [HTTP::header value $aHeader]"
        }
    }
}