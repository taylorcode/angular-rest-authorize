'use strict'

###*
 # @ngdoc overview
 # @name angularRestAuthorize
 # @description
 # Sets up client-side session persistance and authorization. By default it follows
 # REST conventions for creating and obtaining a session, but it exposes it's lifecycle method
 # to override this behaviour
###

angular.module('angularRestAuthorize', ['angularSyncLocalStorage'])

.constant 'AUTH_EVENTS',
  loginSuccess: 'auth-login-success'
  loginFailed: 'auth-login-failed'
  logoutSuccess: 'auth-logout-success'
  sessionTimeout: 'auth-session-timeout'
  notAuthenticated: 'auth-not-authenticated'
  notAuthorized: 'auth-not-authorized'
  userChanged: 'auth-user-changed'

.constant 'USER_ROLES',
  all: '*'
  user: 'user'
  admin: 'admin'

.config ($httpProvider) ->
  # add authorization interceptor to requests
  $httpProvider.interceptors.push ($injector) -> $injector.get 'AuthInterceptor'

.factory 'userSession', ($rootScope) ->

  store: {} # default store is an object object, unless reassigned

  create: (sessionId, userId, userRole) ->
    @_cachedUserId = userId
    @store.id = sessionId
    @store.userId = @_cachedUserId
    @store.userRole = userRole
    
  destroy: ->
    @store.id = null
    @_cachedUserId = @store.userId = null
    @store.userRole = null

.factory 'AuthInterceptor', ($rootScope, $q, AUTH_EVENTS) ->
  responseError: (response) ->

    codeMap =
      401: AUTH_EVENTS.notAuthenticated
      403: AUTH_EVENTS.notAuthorized
      405: AUTH_EVENTS.notAuthenticated # NOTE happens when we're asking for THE user's data, not a specific one
      419: AUTH_EVENTS.sessionTimeout
      440: AUTH_EVENTS.sessionTimeout # microsoft proprietary, probably don't need

    code = codeMap[response.status]
    $rootScope.$broadcast(code, response) if code
    $q.reject response
    
.provider 'AuthService', ->

  # store outside so can reference in provider or instance
  Session = null

  AuthServiceProvider = @

  @resourceUrl = '/api/login'

  @localStorageKey = 'auth-service-session'

  @$get = ($q, $http, $resource, $rootScope, userSession, AUTH_EVENTS, synchronizedLocalStorage) ->

    Session = $resource(AuthServiceProvider.resourceUrl)

    LOCAL_STORAGE_PROP = AuthServiceProvider.localStorageKey
    # define logged out events
    # RELEASENOTE FEATURE NOTE - should we really destroy their session if their not authorized or authenticated?
    loggedOutEvents = [AUTH_EVENTS.notAuthorized, AUTH_EVENTS.notAuthenticated, AUTH_EVENTS.sessionTimeout, AUTH_EVENTS.logoutSuccess]
    # listen for logged out events, destroy the user's session
    _.each loggedOutEvents, (authEvent) -> $rootScope.$on authEvent, -> userSession.destroy()

    calls:
      retain: ->
        Session.get().$promise
      login: (credentials) ->
        Session.save(credentials).$promise
      logout: ->
        Session.delete().$promise

    load: (sessionContainer) ->
       # make the userSession service track with the application session
      userSession.store = sessionContainer
      # update session on rootScope automatically when the localstorage session changes
      synchronizedLocalStorage.synchronize sessionContainer, AuthServiceProvider.localStorageKey, false
      # listen for changes to localStorage externally, respond by letting userSession know that it's values may have been mutated
      $rootScope.$on 'sls:updated', @query.bind @

      @retain()

    loginPromise: null

    retain: ->
      # retain session of user logged in, or not
      @loginPromise = @calls.retain()

      .then (session) =>
        # update the session (which will update $rootScope.session)
        userSession.create session.token, session.id, 'user'
        # store this to track when the user on the session changes (ls string is a singleton, so we need a way to compare the session in the app instance to the singleton session)
        userSession._cachedUserId = userSession.store.userId
        # update session on localstorage to be the current session
        window.localStorage[AuthServiceProvider.localStorageKey] = angular.toJson userSession.store
        $rootScope.$broadcast('AuthService:load', session)
        session

    # $q needed for mock test
    logout: ->
      # this will destroy the user's session if their not authenticated, otherwise it will do nothing and return false
      @calls.logout()
      .then (response) =>
        # reassign loginPromise to rejected promise
        @loginPromise = @loginPromise.then -> $q.reject('user has logged out')
        # need to check if destruction was successful with .catch
        $rootScope.$broadcast(AUTH_EVENTS.logoutSuccess)
        response

    login: (credentials) ->

      # assign loginPromise to new promise
      @loginPromise = @calls.login(credentials)
        .then (session) ->
          userSession.create session.token, session.id, 'user'
          # if we don't have a cached id, then load didn't restore a session, and this is the first session
          if not userSession._cachedUserId
            # FIXME this is the same logic as occurs in retain, merge them / rework the logic
            userSession._cachedUserId = userSession.store.userId
            window.localStorage[AuthServiceProvider.localStorageKey] = angular.toJson userSession.store
          $rootScope.$broadcast('AuthService:load', session)
          $rootScope.$broadcast AUTH_EVENTS.loginSuccess, session
          session
        .catch ->
          $rootScope.$broadcast AUTH_EVENTS.loginFailed
          $q.reject.apply $q, arguments # have to rethrow for some reason
        
    isAuthenticated: ->
      !!userSession.store.userId

    isAuthorized: (authorizedRoles) ->
      @isAuthenticated() and authorizedRoles.indexOf(userSession.store.userRole) isnt -1

    query: ->

      isAuthenticated = @isAuthenticated()

      sessionEvent = ((storageId, sessionId) ->
        if storageId
          # user was logged out and logged in
          if not sessionId
            return AUTH_EVENTS.loginSuccess
          # user switched accounts
          if storageId isnt sessionId
            return AUTH_EVENTS.userChanged
        if not storageId and sessionId
          # user has logged out
          return AUTH_EVENTS.sessionTimeout
        ) userSession.store.userId, userSession._cachedUserId

      # synchronize sessionId with storedId
      userSession._cachedUserId = userSession.store.userId
      # if the user has changed, then retain the new session from the server
      # wait until new user data is gathered .then -> to indicate that the session changed
      if(sessionEvent is AUTH_EVENTS.userChanged or sessionEvent is AUTH_EVENTS.loginSuccess)
        # NOTE should have an event to indicate that the user is changing...
        return @retain().then ->
          $rootScope.$broadcast(sessionEvent)
        # .catch (error) ->
        #   reject('the user changed, but the new session information couldn't be retained from the server because: ', error)
      # notify the application of the session change that occurred
      $rootScope.$broadcast(sessionEvent) if sessionEvent
  return