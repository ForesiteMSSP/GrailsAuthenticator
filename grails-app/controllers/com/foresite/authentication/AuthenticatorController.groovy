package com.foresite.authentication

import java.util.concurrent.*


class AuthenticatorController {

    def authenticatorService
    def grailsApplication
    
    def authenticate() {
        def config = grailsApplication.config.authenticator

        def username = config.getUser()
        if (!username) {
            return redirect(uri: '/')
        }

        def authenticator = Authenticator.findByUsernameIlike(username)

        if (!authenticator) {
            return redirect(uri:"/authenticator/register")
        }
        if (!params.code) {
            return render(view: "authenticate")
        }

        def authCode = params.code.replaceAll("\\s","")

        if (!authCode.isNumber()) {
            if (request.xhr) {
                return [ result: true ]
            }
            else {
                return render(view: "authenticate")
            }
        }

        def timeUnits = new Date().getTime() / TimeUnit.SECONDS.toMillis(30) as Long
                  
        if (authenticatorService.checkCode(authenticator.secretKey, authCode as Long, timeUnits)) {
            authenticator.lastAuthentication = new Date()
            authenticator.save(flush:true)

            if (request.xhr) {
                return [ result: true ]
            }
            else {
                return redirect(uri: params.next ? params.next : "/")
            }
        }
        else {
            authenticator.failedAuthentications += 1
            authenticator.save()

            if (request.xhr) {
                return [ result: false ]
            }
            else {
                return render(view: "authenticate")
            }
        }
    }
    
    def register() {
        def config = grailsApplication.config.authenticator

        def username = config.getUser()
        if (!username) {
            return redirect(uri: '/')
        }

        def hostname = config.hostname ?: "example.com"
        def issuerName = config.issuerName ?: "Default Issuer"

        if (Authenticator.countByUsernameIlike(username)) {
            return render(view: "error", model: [ message: "An authenticator is already registered to your account, you cannot register another one." ])
        }

        if (!params.code) {
            def key = session['authenticator.key'] ?: authenticatorService.generateKey()
            session['authenticator.key'] = key
            
            def email = username.split("@")
            def url = authenticatorService.generateQRCodeURL(email[0], email.length > 1 ? email[1] : hostname, key, issuerName)
        
            return render(view: "register", model: [ url: url ])
        }
        else {
            def key = session['authenticator.key']
                                  
            def timeUnits = new Date().getTime() / TimeUnit.SECONDS.toMillis(30) as Long
            
            if (!authenticatorService.checkCode(key, params.code as Long, timeUnits)) {
                if (request.xhr) {
                    return [ result: false ]
                }
                else {
                    return render(view: "register", model: [message: "register", error: "Code doesn't match"])
                }
            }
                        
            def authenticator = new Authenticator(secretKey: key, lastAuthentication: new Date(), username: username)
                  
            if (authenticator.save()) {
                session['authenticator.key'] = null

                if (request.xhr) {
                    return [ result: true ]
                }
                else {
                    return render(view: "success", model: [message: "You have successfully setup two factor authentication."])
                }
            }
        }
    }
}
