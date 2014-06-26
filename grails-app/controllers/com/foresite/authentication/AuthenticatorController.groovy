package com.foresite.authentication

import grails.converters.*
import java.util.concurrent.*

class AuthenticatorController {

    def authenticatorService
    def grailsApplication
    
    def index(){
        []
    }
    
    def check(){
        def key = session['authenticator.key']
        
        def timeUnits = new Date().getTime() / TimeUnit.SECONDS.toMillis(30) as Long
        
        return render([result:authenticatorService.checkCode(key, params.code as Long, timeUnits)] as JSON)
    }
    
    def authenticate(){
        
        def authenticatorSessionVarName = grailsApplication.config.authenticator.sessionVariableName ?: "authenticator"
        
        def authenticator = Authenticator.findByUser(grailsApplication.config.authenticator.getUser())
             
        if (!authenticator){
            return redirect(uri:"/authenticator/register")
        }
        
        def key = authenticator.secretKey
        
        def timeUnits = new Date().getTime() / TimeUnit.SECONDS.toMillis(30) as Long
                  
        if (authenticatorService.checkCode(key, params.code as Long, timeUnits)){
            flash.message = "Authentication successful"
          
            authenticator.lastAuthentication = new Date()
                    
            authenticator.save()
            
            session[authenticatorSessionVarName] = authenticator.id
            
            return redirect(uri:"/")
        } else {
            authenticator.failedAuthentications += 1
            authenticator.save()
            
            return [error:"Incorrect code."]
        }
    }
    
    def register(){
        def authenticatorSessionVarName = grailsApplication.config.authenticator.sessionVariableName ?: "authenticator"
        def issuerName = grailsApplication.config.authenticator.issuerName ?: "Default Issuer"
                   
        def username = grailsApplication.config.authenticator.getUser()
        
        if (!params.code){
            def key = session['authenticator.key'] ?: authenticatorService.generateKey()
        
            session['authenticator.key'] = key
            
            def url = authenticatorService.generateQRCodeURL(username.split("@")[0], username.split("@")[1], key, issuerName)
        
            return render(view:"register", model:[key:key, url:url])
        } else {
            def key = session['authenticator.key']
                                  
            def timeUnits = new Date().getTime() / TimeUnit.SECONDS.toMillis(30) as Long
            
            if (!authenticatorService.checkCode(key, params.code as Long, timeUnits)){
                return render(view:"success", model:[message:"register", error:"Code doesn't match"])
            }
                        
            def authenticator = new Authenticator(secretKey:key, lastAuthentication:new Date(), user:username)
                     
            
            
            if (authenticator.save()){
                if (grailsApplication.config.authenticator.useSession){
                    session[authenticatorSessionVarName] = authenticator.id
                }
                
                return render(view:"success", model:[message:"You have successfully setup two factory authentication."])
            } else {
                println authenticator.error
            }
        }
        
        
    }
}
