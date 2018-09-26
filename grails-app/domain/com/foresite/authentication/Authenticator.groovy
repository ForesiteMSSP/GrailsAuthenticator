package com.foresite.authentication

class Authenticator {
    
    String id
    
    String username
    String secretKey
    
    Date dateCreated
    Date lastUpdated
    
    Date lastAuthentication
    
    int failedAuthentications = 0

    static mapping = {
        id generator:"uuid"
    }
}
