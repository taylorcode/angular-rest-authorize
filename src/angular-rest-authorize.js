'use strict';

/**
  * @ngdoc overview
  * @name angularRestAuthorize
  * @description
  * Sets up client-side session persistance and authorization. By default it follows
  * REST conventions for creating and obtaining a session, but it exposes it's lifecycle method
  * to override this behaviour
 */
angular.module('angularRestAuthorize', ['angularSyncLocalStorage']).constant('AUTH_EVENTS', {
  loginSuccess: 'auth-login-success',
  loginFailed: 'auth-login-failed',
  logoutSuccess: 'auth-logout-success',
  sessionTimeout: 'auth-session-timeout',
  notAuthenticated: 'auth-not-authenticated',
  notAuthorized: 'auth-not-authorized',
  userChanged: 'auth-user-changed'
}).constant('USER_ROLES', {
  all: '*',
  user: 'user',
  admin: 'admin'
}).config(function($httpProvider) {
  return $httpProvider.interceptors.push(function($injector) {
    return $injector.get('AuthInterceptor');
  });
}).factory('userSession', function($rootScope) {
  return {
    store: {},
    create: function(sessionId, userId, userRole) {
      this._cachedUserId = userId;
      this.store.id = sessionId;
      this.store.userId = this._cachedUserId;
      return this.store.userRole = userRole;
    },
    destroy: function() {
      this.store.id = null;
      this._cachedUserId = this.store.userId = null;
      return this.store.userRole = null;
    }
  };
}).factory('AuthInterceptor', function($rootScope, $q, AUTH_EVENTS) {
  return {
    responseError: function(response) {
      var code, codeMap;
      codeMap = {
        401: AUTH_EVENTS.notAuthenticated,
        403: AUTH_EVENTS.notAuthorized,
        405: AUTH_EVENTS.notAuthenticated,
        419: AUTH_EVENTS.sessionTimeout,
        440: AUTH_EVENTS.sessionTimeout
      };
      code = codeMap[response.status];
      if (code) {
        $rootScope.$broadcast(code, response);
      }
      return $q.reject(response);
    }
  };
}).provider('AuthService', function() {
  var AuthServiceProvider, Session;
  Session = null;
  AuthServiceProvider = this;
  this.resourceUrl = '/api/login';
  this.localStorageKey = 'auth-service-session';
  this.$get = function($q, $http, $resource, $rootScope, userSession, AUTH_EVENTS, synchronizedLocalStorage) {
    var LOCAL_STORAGE_PROP, loggedOutEvents;
    Session = $resource(AuthServiceProvider.resourceUrl);
    LOCAL_STORAGE_PROP = AuthServiceProvider.localStorageKey;
    loggedOutEvents = [AUTH_EVENTS.notAuthorized, AUTH_EVENTS.notAuthenticated, AUTH_EVENTS.sessionTimeout, AUTH_EVENTS.logoutSuccess];
    _.each(loggedOutEvents, function(authEvent) {
      return $rootScope.$on(authEvent, function() {
        return userSession.destroy();
      });
    });
    return {
      calls: {
        retain: function() {
          return Session.get().$promise;
        },
        login: function(credentials) {
          return Session.save(credentials).$promise;
        },
        logout: function() {
          return Session["delete"]().$promise;
        }
      },
      load: function(sessionContainer) {
        userSession.store = sessionContainer;
        synchronizedLocalStorage.synchronize(sessionContainer, AuthServiceProvider.localStorageKey, false);
        $rootScope.$on('sls:updated', this.query.bind(this));
        return this.retain();
      },
      loginPromise: null,
      retain: function() {
        return this.loginPromise = this.calls.retain().then((function(_this) {
          return function(session) {
            userSession.create(session.token, session.id, 'user');
            userSession._cachedUserId = userSession.store.userId;
            window.localStorage[AuthServiceProvider.localStorageKey] = angular.toJson(userSession.store);
            $rootScope.$broadcast('AuthService:load', session);
            return session;
          };
        })(this));
      },
      logout: function() {
        return this.calls.logout().then((function(_this) {
          return function(response) {
            _this.loginPromise = _this.loginPromise.then(function() {
              return $q.reject('user has logged out');
            });
            $rootScope.$broadcast(AUTH_EVENTS.logoutSuccess);
            return response;
          };
        })(this));
      },
      login: function(credentials) {
        return this.loginPromise = this.calls.login(credentials).then(function(session) {
          userSession.create(session.token, session.id, 'user');
          if (!userSession._cachedUserId) {
            userSession._cachedUserId = userSession.store.userId;
            window.localStorage[AuthServiceProvider.localStorageKey] = angular.toJson(userSession.store);
          }
          $rootScope.$broadcast('AuthService:load', session);
          $rootScope.$broadcast(AUTH_EVENTS.loginSuccess, session);
          return session;
        })["catch"](function() {
          $rootScope.$broadcast(AUTH_EVENTS.loginFailed);
          return $q.reject.apply($q, arguments);
        });
      },
      isAuthenticated: function() {
        return !!userSession.store.userId;
      },
      isAuthorized: function(authorizedRoles) {
        return this.isAuthenticated() && authorizedRoles.indexOf(userSession.store.userRole) !== -1;
      },
      query: function() {
        var isAuthenticated, sessionEvent;
        isAuthenticated = this.isAuthenticated();
        sessionEvent = (function(storageId, sessionId) {
          if (storageId) {
            if (!sessionId) {
              return AUTH_EVENTS.loginSuccess;
            }
            if (storageId !== sessionId) {
              return AUTH_EVENTS.userChanged;
            }
          }
          if (!storageId && sessionId) {
            return AUTH_EVENTS.sessionTimeout;
          }
        })(userSession.store.userId, userSession._cachedUserId);
        userSession._cachedUserId = userSession.store.userId;
        if (sessionEvent === AUTH_EVENTS.userChanged || sessionEvent === AUTH_EVENTS.loginSuccess) {
          return this.retain().then(function() {
            return $rootScope.$broadcast(sessionEvent);
          });
        }
        if (sessionEvent) {
          return $rootScope.$broadcast(sessionEvent);
        }
      }
    };
  };
});

// ---
// generated by coffee-script 1.9.0