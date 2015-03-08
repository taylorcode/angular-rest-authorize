'use strict'

###*
 # @ngdoc overview
 # @name authLogout
 # @description
 # Attribute directive, when this directive element is clicked
 # it calls on the AuthService to log the user out.
###

angular.module 'icrAuth'

.directive 'authLogout', ($location, AuthService) ->
	restrict: 'A'
	link: (scope, elem) ->
		elem.click -> AuthService.logout()