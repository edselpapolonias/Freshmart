# inventory/context_processors.py
def profile_picture(request):
    if request.user.is_authenticated:
        profile = getattr(request.user, 'userprofile', None)
        if profile and profile.picture:
            return {'profile_picture_url': profile.picture.url}
    return {'profile_picture_url': None}
