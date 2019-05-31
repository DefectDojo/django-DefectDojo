def social_uid(backend, details, response, *args, **kwargs):
	uid = backend.get_user_id(details, response)
	# Used for most backends
	if uid:
		return {'uid': uid}
	# Until OKTA PR in social-core is merged
	# This modified way needs to work
	else:
		return {'uid': response.get('preferred_username')}

# Modify the status of new users to staff 
def modify_permissions(backend, uid, user=None, social=None, *args, **kwargs):
	if kwargs.get('is_new') == True:
		user.is_staff = True 
