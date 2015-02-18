# wrath
Wrath - redis-backed auth - rauth - wrath

There are:
        Identities
        Actors
        Roles

An Identity     is referred to through a UUID and is a pair of [id, password], where the id and password are JSON strings - There is a root identity - An Identities id MUST BE GLOBALLY UNIQUE
A Role          is referred to through a UUID and is a JSON string - There is a root role - A Role MUST BE GLOBALLY UNIQUE
An Actor        is referred to through a UUID and is a JSON object - There is a root actor
A relationship  is referred to through a UUID, with the following as possible relationships:
        An Identity     can have zero or *one* Actor(s) - the root identity is associated with the root actor
        An Actor        can have zero or more Identities
        An Actor        can have zero or more Roles
        A Role          can have zero or more Actors - the root actor is associated with the root role

Token: the temporary proof of having provided a valid Identity

Authentication: the process of an Actor providing an Identity and recieving a Token

Authorization: the verification that a Token is related to a Role
        Nothing can be done without a valid Token
        The root role represents authorization to do anything in the system - except delete the root identity, root actor, root role, or the relation of root identity to root actor, or the relation of root actor to root role
        No other Role represents the authorization for any action in the system

Redis Key Types:
        UNIQUE:IDENTITY         set of Identity ids
        UNIQUE:ROLE             set of Role values

        IDENTITY:uuid           string
        ACTOR:uuid              string
        ROLE:uuid               string

        IDENTITY:LIST           set of 'iuuids'
        ACTOR:LIST              set of 'auuids'
        ROLE:LIST               set of 'ruuids'

        ACTOR:IDENTITY:auuid    set of 'iuuids'
        IDENTITY:ACTOR:iuuid    string of auuid

        ACTOR:ROLE:auuid        set of 'ruuids'
        ROLE:ACTOR:ruuid        set of 'auuids'


The root role is a Role who's value is the JSON string `"root"`

A Token is a UUID whos value is an iuuid, see the '/t' definition below

Without a token, a 401 is returned
Without a valid token representing the authorization of the root role, a 403 is returned

        /i
                POST /i (create an Identity - body is json array - first value is anything (a uuid or email are common) and it is required to be unique - second value is password - response is uuid - 201 or 400)
                GET /i (get all identities - response is object of uuids to json arrays - 200)
                GET /i/{uuid} (get uuid or email associated with the specific Identity - 200 or 404)
                PUT /i/{uuid} (set json array associated with the specific Identity - 200 or 400 or 404)
                DELETE /i/{uuid} (200 or 404)
        /a
                POST /a (create an Actor - body is json object - response is uuid - 201 or 400)
                GET /a (get all Actors - response is object of uuids to json objects - 200)
                GET /a/{uuid} (get json object associated with the specific Actor - 200 or 404)
                PUT /a/{uuid} (set json object associated with the specific Actor - 200 or 400 or 404)
                DELETE /a/{uuid} (200 or 404)
        /r
                POST /r (create a Role - body is json string and is required to be unique - response is uuid - 201 or 400)
                GET /r (get all Roles - response is object of uuids to strings - 200)
                GET /r/{uuid} (get json string associated with the specific Role - 200 or 404)
                PUT /r/{uuid} (set json string associated with the specific Role - 200 or 400 or 404)
                DELETE /r/{uuid} (200 or 404)
        /ai
                POST /ai/{auuid}/{iuuid} (associate an Actor with an Identity - 201 or 400)
                GET /ai (get all associations of Actors with identities - response is object of auuid to array of iuuids - 200)
                GET /ai/{uuid} (get json array of associated uuids - 200 or 404)
                DELETE /ai/{auuid}/{iuuid} (200 or 404)
        /ar
                POST /ar/{auuid}/{ruuid} (associate an Actor with a Role - 201 or 400)
                GET /ar (get all associations of Actors with Roles - response is object of auuid to array of ruuids - 200)
                GET /ar/{uuid} (get json array of associated uuids - 200 or 404)
                DELETE /ar/{auuid}/{ruuid} (200 or 404)
        /z
                GET /z/{url encoded uuid or email} (response is array of Roles associated with Identity - 200 or 404)
        /t
                GET /t (authorization header has "BASIC " prefixed b64 of colon joined Identity pair - response is tuuid - 200 or 404)


