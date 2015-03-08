# angularRestAuthorize

Angular session persistance using Local Storage. Automatically synchronizes user sessions across windows, across a single mirrored session object.

### Basic Setup

First, add this module to your application:

	angular.module('myApp', ['angularRestAuthorize'])


By default, `angularRestAuthorize` is configured to perform Rest operations on the resource `/api/login`. If your service is Rest compliant, but you would like to switch this path, it is configurable on the provider:

	AuthServiceProvider.resourceUrl = 'https://external-auth-service.com/api/v2/session'

### Methods

#### AuthService.load()

	let mySessionContainer = {}

	AuthService.load(mySessionContainer)

In this example, `mySessionContainer` will automatically be synchronized with the user's session and localStorage. This synchronization occurs across browser windows, so the `mySessionContainer` objects in all windows, will be identical.

#### AuthService.login(credentials)

By default, this will issue a `POST` request to the configured `resourceUrl`. This is configurable by changing the `login` call function in the provider:

	AuthService.calls.login = function (credentials) {
		return myApi.user.signIn(credentials).then(function (session) {
			return {
				token: session.authentication_token,
				id: session.id,
				role: 'user'
			}
		})
	}

The expected return of this method is a promise, that when unwrapped contains a `token`, `id`, and `role` property.

#### AuthService.logout()

By default, this will issue a `DELETE` request to the configured `resourceUrl`. This is configurable by changing the `logout` call function in the provider:

	AuthService.calls.logout = function () {

		return myApi.user.signOut().then(function () {
			// do something
		});

	}

#### AuthService.retain()

This method this is automatically called to obtain the user's session when the service is first loaded. By default, it wil issue a `GET` request to the configured `resourceUrl`, and the response will be used to create the session. You can configure this by changing the `retain` call in the provider.

	AuthService.calls.retain = function () {

		if(persistData.user) {
			defer.resolve({
				token: persistData.authToken,
				id: persistData.user.id,
				role: 'user'
			})
		} else {
			defer.reject('user is not logged in - there is no authorization token.')
		}
	}

### Events

Events will broadcast on `$rootScope` throughout the lifecycle of the authorization process. These events are defined in the `AUTH_EVENTS` constant:

	{
		loginSuccess: 'auth-login-success',
		loginFailed: 'auth-login-failed',
		logoutSuccess: 'auth-logout-success',
		sessionTimeout: 'auth-session-timeout',
		notAuthenticated: 'auth-not-authenticated',
		notAuthorized: 'auth-not-authorized',
		userChanged: 'auth-user-changed'
	}

There is also a `AuthService:load` event that is broadcasted when the auth service loads, on login, on session restore, or on user change.

Example use:

	// when the auth service loads, on login, on session restore, on user change
	$rootScope.$on('AuthService:load', function (event, user) {

		$rootScope.globals.user = user

	})

### Defining User Roles


The `USER_ROLES` constant contains some default user roles:

	{
	  all: '*',
	  user: 'user',
	  admin: 'admin'
	}

You can override these roles by creating your own constant with the same name. These roles are used to determine if the user is authorized for a specific resource. See `isAuthorized` method:

#### AuthService.isAuthorized(authorizedRoles)

`authorizedRoles` is an array of roles that the user's session will be compared against. For example:

	AuthService.isAuthorized(['user'])

By placing this in the resolve of the router, this can be used to conditionally allow a user to see a specific view.

#### AuthService.isAuthenticated()

Determines if the user is authenticated and the session exists.

### userSession Service

The `userSession` storage is automatically synchronized with the session resource, and contains the properties: `id`, `userId`, and `userRole`

