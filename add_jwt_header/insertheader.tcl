when RULE_INIT priority 100 {

    # set static::jwt "UNSET"
}

when ACCESS_POLICY_AGENT_EVENT priority 100 {

    set pspid [ACCESS::policy agent_id]
    log local0. "PSP iRuleID $pspid"

    if { $pspid eq "psp_add_jwt" } {
        ACCESS::session data set "session.custom.userdata.jwt" [ACCESS::session data get -secure "session.oauth.client.last.id_token"]
        set path [HTTP::path]

        log local0. "Adding [string range [ACCESS::session data get "session.custom.userdata.jwt"] 0 15] on $path"
    }

}

when ACCESS_PER_REQUEST_AGENT_EVENT priority 100 {
    set prpid [ACCESS::perflow get perflow.irule_agent_id]

    log local0. "PRP iRuleID $prpid"

    if { $prpid eq "prp_add_jwt" } {

        # set jwt [ACCESS::session data get "session.oauth.client.last.id_token"]
        set path [HTTP::path]

        HTTP::header insert "Authorization" [ACCESS::session data get "session.custom.userdata.jwt"]
        log local0. "Adding JWT ([string range [ACCESS::session data get "session.custom.userdata.jwt"] 0 15]) to Authorization header on $path"
    }
}

when HTTP_REQUEST_RELEASE priority 100 {
    foreach aHeader [HTTP::header names] {
        log local0. "HTTP Request Headers: $aHeader: [HTTP::header value $aHeader]"
    }
}