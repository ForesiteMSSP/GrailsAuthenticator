import groovy.time.TimeCategory


class AuthenticatorFilters {
    
    def grailsApplication
    
    def filters = {
        adminCheck(controller: '*', action: '*') {
            before = {
                def config = grailsApplication.config.authenticator

                if (config.isEnabledForUser()) {
                    def username = config.getUser()
                    if (!username) {
                        redirect(uri: '/')
                        return false
                    }

                    def expireMinutes = config.expireMinutes
                    if (!expireMinutes) {
                        expireMinutes = (config.expireDays ?: 30) * 1440
                    }

                    def excludeControllers = config.excludeControllers ?: []
                
                    def authenticator = com.foresite.authentication.Authenticator.findByUsernameIlike(username)

                    def authenticated = false
                    use (TimeCategory) {
                        authenticated = authenticator ? authenticator.lastAuthentication?.after(expireMinutes.minutes.ago) : false
                    }
                
                    if (config.enabled
                        && controllerName != 'authenticator'
                        && controllerName != 'login' 
                        && !excludeControllers.contains(controllerName)
                        && !authenticated) {

                        if (request.xhr) {
                            render(status: 401)
                        }
                        else {
                            redirect(uri: "/authenticator/authenticate?next=/${controllerName ? "$controllerName" : ""}${actionName ? "/$actionName" : ""}${params.id ? "/$params.id" : ""}")
                        }

                        return false
                    }
                }
                
                return true
            }
        }
    }
}

